import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:win32/win32.dart';

import 'secret_vault.dart';
import 'vault_internals.dart';

/// `CRYPTPROTECT_UI_FORBIDDEN` from `dpapi.h`; not exported by `package:win32` 6.x.
const int _cryptProtectUiForbidden = 0x1;

/// Stores secrets as DPAPI-protected blobs under the user's local
/// application-data directory.
///
/// `CryptProtectData` binds a blob to the current Windows user on the current
/// machine, and [write] mixes `"$namespace/$alias"` in as optional entropy, so a
/// blob cannot be replayed by a different user, a different machine or a
/// different alias.
///
/// A blob that no longer decrypts (account removed, machine reimaged, profile
/// roamed) makes [read] return `null` rather than throw, because there is
/// nothing the app can do about it.
class WindowsSecretVault implements SecretVault {
  factory WindowsSecretVault({
    String namespace = kDefaultVaultNamespace,
    String? directory,
    int maxSecretBytes = kMaxVaultSecretBytes,
  }) {
    validateNamespace(namespace);
    validateMaxSecretBytes(maxSecretBytes);
    return WindowsSecretVault._(namespace, directory, maxSecretBytes);
  }

  const WindowsSecretVault._(
    this.namespace,
    this._directory,
    this.maxSecretBytes,
  );

  final String namespace;
  final String? _directory;

  @override
  final int maxSecretBytes;

  /// `<LocalAppData>\<namespace>\secure_vault`, or [directory] when the host
  /// app wants to place the blobs itself.
  String get vaultDirectory {
    final String? base = _directory ?? Platform.environment['LOCALAPPDATA'];
    if (base == null || base.isEmpty) {
      throw const VaultUnavailableException(
        'Cannot locate the local application-data directory (%LOCALAPPDATA% is '
        'unset); pass an explicit directory to WindowsSecretVault.',
      );
    }
    return _directory == null ? '$base\\$namespace\\secure_vault' : base;
  }

  @override
  Future<void> write(String alias, Uint8List secret) async {
    validateAlias(alias);
    validateSecret(secret, maxSecretBytes);
    final String dir = vaultDirectory;
    final String file = vaultFileName(namespace, alias);
    final String entropy = vaultStorageKey(namespace, alias);
    final Uint8List copy = Uint8List.fromList(secret);
    final VaultWire wire;
    try {
      wire = await Isolate.run(() => _writeSync(dir, file, entropy, copy));
    } finally {
      zeroSecret(copy);
    }
    vaultCheckWire('write "$alias"', wire);
  }

  @override
  Future<Uint8List?> read(String alias) async {
    validateAlias(alias);
    final String dir = vaultDirectory;
    final String file = vaultFileName(namespace, alias);
    final String entropy = vaultStorageKey(namespace, alias);
    final VaultWire wire = await Isolate.run(
      () => _readSync(dir, file, entropy),
    );
    if (wire.status == kVaultNotFound) {
      return null;
    }
    vaultCheckWire('read "$alias"', wire);
    return wire.data;
  }

  @override
  Future<void> delete(String alias) async {
    validateAlias(alias);
    final String dir = vaultDirectory;
    final String file = vaultFileName(namespace, alias);
    final VaultWire wire = await Isolate.run(() => _deleteSync(dir, file));
    vaultCheckWire('delete "$alias"', wire);
  }

  @override
  Future<bool> contains(String alias) async {
    validateAlias(alias);
    final String dir = vaultDirectory;
    final String file = vaultFileName(namespace, alias);
    final VaultWire wire = await Isolate.run(() => _containsSync(dir, file));
    vaultCheckWire('check "$alias"', wire);
    return wire.status == kVaultOk;
  }
}

VaultWire _writeSync(String dir, String file, String entropy, Uint8List plain) {
  String temp = '';
  try {
    Directory(dir).createSync(recursive: true);
    final String target = '$dir\\$file';
    temp = '$target.${DateTime.now().microsecondsSinceEpoch}.tmp';
    final VaultWire wire = using((Arena arena) {
      final Pointer<CRYPT_INTEGER_BLOB> out = arena<CRYPT_INTEGER_BLOB>();
      final int error = _protect(plain, entropy, out, arena);
      if (error != 0) {
        return vaultFailure(error);
      }
      final Uint8List blob = _readBlob(out);
      final Uint8List framed = Uint8List(1 + blob.length)
        ..[0] = kVaultBlobVersion
        ..setRange(1, 1 + blob.length, blob);
      File(temp).writeAsBytesSync(framed, flush: true);
      final bool moved = MoveFileEx(
        PCWSTR(temp.toNativeUtf16(allocator: arena)),
        PCWSTR(target.toNativeUtf16(allocator: arena)),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
      ).value;
      return moved ? vaultOk() : vaultFailure(GetLastError());
    });
    if (wire.status != kVaultOk) {
      _tryDelete(temp);
    }
    return wire;
  } on FileSystemException catch (e) {
    _tryDelete(temp);
    return vaultFailure(e.osError?.errorCode ?? -1);
  }
}

VaultWire _readSync(String dir, String file, String entropy) {
  final File stored = File('$dir\\$file');
  if (!stored.existsSync()) {
    return vaultNotFound();
  }
  try {
    return using((Arena arena) {
      final Uint8List framed = stored.readAsBytesSync();
      if (framed.length < 2 || framed[0] != kVaultBlobVersion) {
        return vaultFailure(framed.isEmpty ? -1 : framed[0]);
      }
      return _unprotect(Uint8List.sublistView(framed, 1), entropy, arena);
    });
  } on FileSystemException catch (e) {
    return vaultFailure(e.osError?.errorCode ?? -1);
  }
}

VaultWire _deleteSync(String dir, String file) {
  try {
    final File stored = File('$dir\\$file');
    if (stored.existsSync()) {
      stored.deleteSync();
    }
    return vaultOk();
  } on FileSystemException catch (e) {
    return vaultFailure(e.osError?.errorCode ?? -1);
  }
}

VaultWire _containsSync(String dir, String file) =>
    File('$dir\\$file').existsSync() ? vaultOk() : vaultNotFound();

/// Returns 0 on success, otherwise the `GetLastError` code.
int _protect(
  Uint8List plain,
  String entropy,
  Pointer<CRYPT_INTEGER_BLOB> out,
  Allocator arena,
) {
  final Uint8List entropyBytes = Uint8List.fromList(utf8.encode(entropy));
  final Pointer<Uint8> plainBuf = _buffer(plain, arena);
  final Pointer<Uint8> entropyBuf = _buffer(entropyBytes, arena);
  final Win32Result<bool> result = CryptProtectData(
    _blob(plain, plainBuf, arena),
    null,
    _blob(entropyBytes, entropyBuf, arena),
    nullptr,
    _cryptProtectUiForbidden,
    out,
  );
  plainBuf.asTypedList(plain.length).fillRange(0, plain.length, 0);
  return result.value ? 0 : result.error;
}

/// A DPAPI failure means "this blob is not ours to open", which the contract
/// reports as absent rather than broken.
VaultWire _unprotect(Uint8List blob, String entropy, Allocator arena) {
  final Uint8List entropyBytes = Uint8List.fromList(utf8.encode(entropy));
  final Pointer<CRYPT_INTEGER_BLOB> out = arena<CRYPT_INTEGER_BLOB>();
  final Win32Result<bool> result = CryptUnprotectData(
    _blob(blob, _buffer(blob, arena), arena),
    null,
    _blob(entropyBytes, _buffer(entropyBytes, arena), arena),
    nullptr,
    _cryptProtectUiForbidden,
    out,
  );
  if (!result.value) {
    return vaultNotFound();
  }
  final Uint8List plain = _readBlob(out);
  out.ref.pbData.asTypedList(out.ref.cbData).fillRange(0, out.ref.cbData, 0);
  LocalFree(HLOCAL(out.ref.pbData));
  return vaultOk(plain);
}

Pointer<Uint8> _buffer(Uint8List bytes, Allocator arena) {
  final Pointer<Uint8> buf = arena<Uint8>(bytes.length);
  buf.asTypedList(bytes.length).setAll(0, bytes);
  return buf;
}

Pointer<CRYPT_INTEGER_BLOB> _blob(
  Uint8List bytes,
  Pointer<Uint8> buf,
  Allocator arena,
) => arena<CRYPT_INTEGER_BLOB>()
  ..ref.cbData = bytes.length
  ..ref.pbData = buf;

Uint8List _readBlob(Pointer<CRYPT_INTEGER_BLOB> blob) =>
    Uint8List.fromList(blob.ref.pbData.asTypedList(blob.ref.cbData));

void _tryDelete(String path) {
  if (path.isEmpty) {
    return;
  }
  try {
    File(path).deleteSync();
  } on FileSystemException {
    // Best-effort cleanup of a temp file that never became the vault entry.
  }
}
