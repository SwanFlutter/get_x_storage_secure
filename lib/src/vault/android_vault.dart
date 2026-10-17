import 'dart:isolate';
import 'dart:typed_data';

import 'package:jni/jni.dart';
import 'package:jni_flutter/jni_flutter.dart' show androidApplicationContext;

import 'android_bindings.dart';
import 'secret_vault.dart';
import 'vault_internals.dart';
import 'vault_options.dart';

/// Status frame layout produced by the Kotlin helper:
/// `[status][errorCode low][errorCode high][payload...]`, with the status codes
/// from [vault_internals] and a little-endian 16-bit error code.
const int _frameHeaderBytes = 3;

/// AndroidKeyStore is a real hardware/daemon-backed service. It is missing on
/// heavily modified devices and on some emulators; both cases are reported as
/// unavailable rather than as a lost secret.
const String _unavailableHint =
    'AndroidKeyStore could not be reached. It needs a device with a working '
    'keystore daemon; some emulators and rooted images do not provide one.';

/// Thrown by the JNI layer when the helper class or the keystore service cannot
/// be reached at all, which is a facility problem rather than a data problem.
const String _jniHint =
    'The vault helper class could not be called through JNI. Run '
    '`dart run tool/jnigen.dart` after changing the Kotlin helper and make '
    'sure the app registers the jni_flutter plugin.';

/// AndroidKeyStore answers this way while the authentication window of a gated
/// key is closed, so the secret stays intact and a retry can work.
const String _authHint =
    'This key needs the user to have authenticated recently: unlock the device '
    'or run a BiometricPrompt, then call again.';

/// Android vault backed by one non-exportable AES-256-GCM key per alias in
/// `AndroidKeyStore`, with the ciphertext in a file under `noBackupFilesDir`.
///
/// A blob is `[version][12-byte IV][ciphertext and 16-byte GCM tag]`; the
/// namespace-prefixed alias is both the KeyStore entry name and the
/// additional-authenticated-data, so a blob cannot be replayed under another
/// alias. Because the key never leaves the keystore, app code can only ask the
/// OS to decrypt a blob it already owns.
///
/// Recovery failures — a key destroyed by a lock-screen change, an
/// `AEADBadTagException`, an `UnrecoverableKeyException`, or a blob whose key
/// is gone — are indistinguishable from absence from the app's point of view, so
/// the helper deletes both blob and entry and [read] returns `null`. A
/// structurally invalid blob is a [VaultOperationException] instead, since
/// keeping it would hide a corruption the caller may want to know about.
///
/// Auto Backup restores files but never KeyStore keys, so a migrated install
/// meets blobs it cannot open; exclude them with `dataExtractionRules` (or
/// `fullBackupContent` below API 31). See NOTES.md.
///
/// Every call runs on a throwaway isolate: generating a StrongBox key and
/// enqueuing cipher work routinely take tens of milliseconds and must not stall
/// the UI isolate.
class AndroidSecretVault implements SecretVault {
  factory AndroidSecretVault({
    String namespace = kDefaultVaultNamespace,
    AndroidVaultOptions options = const AndroidVaultOptions(),
    int maxSecretBytes = kMaxVaultSecretBytes,
  }) {
    validateNamespace(namespace);
    validateMaxSecretBytes(maxSecretBytes);
    options.validate();
    return AndroidSecretVault._(namespace, options, maxSecretBytes);
  }

  const AndroidSecretVault._(this.namespace, this.options, this.maxSecretBytes);

  final String namespace;
  final AndroidVaultOptions options;

  @override
  final int maxSecretBytes;

  @override
  Future<void> write(String alias, Uint8List secret) async {
    validateAlias(alias);
    validateSecret(secret, maxSecretBytes);
    final AndroidVaultOptions gate = options;
    final Uint8List copy = Uint8List.fromList(secret);
    final VaultWire wire;
    try {
      wire = await Isolate.run(
        () => _writeSync(
          namespace,
          alias,
          gate.requireUserAuthentication,
          gate.authenticationTimeoutSeconds,
          copy,
        ),
      );
    } finally {
      zeroSecret(copy);
    }
    vaultCheckWire('write "$alias"', wire);
  }

  @override
  Future<Uint8List?> read(String alias) async {
    validateAlias(alias);
    final VaultWire wire = await Isolate.run(() => _readSync(namespace, alias));
    if (wire.status == kVaultNotFound) {
      return null;
    }
    vaultCheckWire('read "$alias"', wire);
    return wire.data;
  }

  @override
  Future<void> delete(String alias) async {
    validateAlias(alias);
    vaultCheckWire(
      'delete "$alias"',
      await Isolate.run(() => _deleteSync(namespace, alias)),
    );
  }

  @override
  Future<bool> contains(String alias) async {
    validateAlias(alias);
    final VaultWire wire = await Isolate.run(
      () => _containsSync(namespace, alias),
    );
    if (wire.status == kVaultNotFound) {
      return false;
    }
    vaultCheckWire('check "$alias"', wire);
    return true;
  }
}

VaultWire _writeSync(
  String namespace,
  String alias,
  bool requireAuth,
  int authTimeoutSeconds,
  Uint8List secret,
) {
  final _VaultArgs args = _VaultArgs(namespace, alias);
  // The array handed to Java outlives this isolate's control, and the JVM offers
  // no way to wipe it, which is why the plaintext is encrypted straight into a
  // KeyStore-backed blob and never written anywhere else.
  final JByteArray input = JByteArray.of(secret);
  JByteArray? frame;
  try {
    frame = VaultKeyStore.write(
      args.context,
      args.fileName,
      args.keyName,
      args.keyName,
      input,
      requireAuth,
      authTimeoutSeconds,
    );
    return _decode(frame);
  } on Object catch (error) {
    return _wireFromJniError(error);
  } finally {
    frame?.release();
    input.release();
    args.release();
  }
}

VaultWire _readSync(String namespace, String alias) {
  final _VaultArgs args = _VaultArgs(namespace, alias);
  JByteArray? frame;
  try {
    frame = VaultKeyStore.read(
      args.context,
      args.fileName,
      args.keyName,
      args.keyName,
    );
    return _decode(frame);
  } on Object catch (error) {
    return _wireFromJniError(error);
  } finally {
    frame?.release();
    args.release();
  }
}

VaultWire _deleteSync(String namespace, String alias) {
  final _VaultArgs args = _VaultArgs(namespace, alias);
  JByteArray? frame;
  try {
    frame = VaultKeyStore.delete(args.context, args.fileName, args.keyName);
    return _decode(frame);
  } on Object catch (error) {
    return _wireFromJniError(error);
  } finally {
    frame?.release();
    args.release();
  }
}

VaultWire _containsSync(String namespace, String alias) {
  final _VaultArgs args = _VaultArgs(namespace, alias);
  JByteArray? frame;
  try {
    frame = VaultKeyStore.contains(args.context, args.fileName);
    return _decode(frame);
  } on Object catch (error) {
    return _wireFromJniError(error);
  } finally {
    frame?.release();
    args.release();
  }
}

/// The Java arguments one vault operation needs, all local references that
/// belong to the worker isolate which created them.
///
/// [keyName] is the namespace-prefixed alias, used by the helper both as the
/// KeyStore entry name and as the GCM additional authenticated data.
class _VaultArgs {
  _VaultArgs(String namespace, String alias)
    : context = androidApplicationContext,
      fileName = vaultFileName(namespace, alias).toJString(),
      keyName = vaultStorageKey(namespace, alias).toJString();

  final JObject context;
  final JString fileName;
  final JString keyName;

  void release() {
    keyName.release();
    fileName.release();
    context.release();
  }
}

VaultWire _decode(JByteArray frame) {
  final int length = frame.length;
  if (length < _frameHeaderBytes) {
    return vaultFailure(-1);
  }
  // JByteArray hands back signed bytes, so re-read them as the unsigned frame
  // the rest of the vault uses.
  final Uint8List bytes = Uint8List.fromList(frame.getRange(0, length));
  try {
    final int status = bytes[0];
    final int osCode = bytes[1] | (bytes[2] << 8);
    if (status == kVaultOk) {
      // [sublist] copies, so wiping the frame below cannot touch the payload.
      final Uint8List payload = bytes.sublist(_frameHeaderBytes);
      return vaultOk(payload.isEmpty ? null : payload);
    }
    return switch (status) {
      kVaultNotFound => vaultNotFound(),
      kVaultAuthRequired => vaultAuthRequired(
        osCode: osCode,
        detail: _authHint,
      ),
      kVaultUnavailable => vaultUnavailable(
        osCode: osCode,
        detail: _unavailableHint,
      ),
      _ => vaultFailure(osCode),
    };
  } finally {
    zeroSecret(bytes);
  }
}

VaultWire _wireFromJniError(Object error) {
  // The Kotlin helper catches its own failures and answers with a frame, so a
  // throwable crossing JNI means the class or the service could not be reached.
  // Java messages name classes and aliases, never key material, but they are
  // still truncated to keep exception text short.
  final String message = error is JThrowable
      ? error.message
      : error.runtimeType.toString();
  final String brief = message.length > 200
      ? '${message.substring(0, 200)}…'
      : message;
  return vaultUnavailable(osCode: -1, detail: '$_jniHint ($brief)');
}
