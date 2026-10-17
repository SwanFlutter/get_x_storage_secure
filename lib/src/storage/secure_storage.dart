import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../vault/secret_vault.dart';
import '../vault/vault_factory.dart';
import '../vault/vault_internals.dart';
import '../vault/vault_options.dart';
import 'blob_store.dart';

/// Whether a key gained or lost its value.
enum SecureStorageChangeKind { written, deleted }

/// One entry of [SecureStorage.changes]. Names the change, never the value.
class SecureStorageChange {
  const SecureStorageChange(this.key, this.kind);

  final String key;
  final SecureStorageChangeKind kind;

  @override
  String toString() => 'SecureStorageChange(${kind.name})';
}

/// A string key–value store whose values live in the operating system's own
/// secret store, on top of [SecretVault].
///
/// * Keys are arbitrary text: each one is hashed to the alias its value is
///   stored under, so no character rule applies to callers and two keys that
///   differ only in case stay distinct — which matters on backends whose native
///   name space is case-insensitive.
/// * Values may be any length: [SecretVault.maxSecretBytes] bounds one write to
///   the OS, and a longer value is split across vault entries and reassembled on
///   read.
/// * [readAll] and [deleteAll] work because the key names themselves are kept as
///   a vault entry: the Android keystore, DPAPI and the Keychain offer no way to
///   enumerate what they hold, so an unindexed value cannot be listed. The index
///   travels through the same OS protection as the values.
/// * [changes] notifies this isolate about writes and deletes made through this
///   instance. It is not a cross-process or cross-device push.
///
/// Reads never throw for a missing value: [read] and [readBytes] answer `null`,
/// and a value the OS can no longer decrypt reads back the same way, since the
/// app cannot recover from that either.
///
/// Dart strings are immutable, so a value written through [write] can outlive
/// this object in the heap. Use [writeBytes] with a buffer you zero yourself
/// when that matters.
class SecureStorage {
  /// Creates the store over the secret vault of the running operating system.
  ///
  /// Throws [UnsupportedError] on the web, where no OS secret store exists.
  factory SecureStorage({
    String namespace = kDefaultVaultNamespace,
    VaultOptions options = const VaultOptions(),
  }) => SecureStorage.fromVault(
    createPlatformVault(namespace: namespace, options: options),
  );

  /// Creates the store over an existing [vault].
  SecureStorage.fromVault(SecretVault vault)
    : _blobs = BlobStore(vault),
      _maxSecretBytes = vault.maxSecretBytes;

  final BlobStore _blobs;
  final int _maxSecretBytes;
  final StreamController<SecureStorageChange> _changes =
      StreamController<SecureStorageChange>.broadcast();

  /// Tail of the queue that serialises mutations, so that two concurrent writes
  /// cannot each read the index and then overwrite each other's copy of it.
  Future<void> _tail = Future<void>.value();

  /// Bytes one value write puts into the vault at a time; a longer value is
  /// split across that many vault entries.
  int get maxSecretBytes => _maxSecretBytes;

  /// Writes and deletes performed through this instance, in order.
  Stream<SecureStorageChange> get changes => _changes.stream;

  /// Stores [value] under [key], replacing any previous value.
  Future<void> write(String key, String value) => _put(key, value);

  /// Stores [value] under [key], replacing any previous value.
  Future<void> writeBytes(String key, Uint8List value) => _putBytes(key, value);

  /// The value stored under [key], or null when there is none.
  ///
  /// Bytes that are not valid UTF-8 decode with replacement characters; read
  /// them back with [readBytes] instead.
  Future<String?> read(String key) async {
    final Uint8List? bytes = await _get(key);
    if (bytes == null) {
      return null;
    }
    final String value = utf8.decode(bytes, allowMalformed: true);
    zeroSecret(bytes);
    return value;
  }

  /// The value stored under [key], or null when there is none.
  Future<Uint8List?> readBytes(String key) => _get(key);

  /// Whether [key] currently has a value.
  Future<bool> containsKey(String key) async {
    _validateKey(key);
    return _blobs.contains(_valueName(key));
  }

  /// Removes the value of [key]; a missing key is a no-op.
  Future<void> delete(String key) async {
    _validateKey(key);
    await _locked(() async {
      await _blobs.delete(_valueName(key));
      await _writeIndex(await _indexWithout(key));
      _emit(key, SecureStorageChangeKind.deleted);
    });
  }

  /// Every key with a value, in the order each was first written.
  ///
  /// A damaged index reads back as empty, which leaves stored values
  /// unreachable by name while [read] of a known key keeps working.
  Future<List<String>> getKeys() => _locked(_readIndex);

  /// Every key with a value, decoded as text.
  Future<Map<String, String>> readAll() async {
    final Map<String, String> values = <String, String>{};
    for (final String key in await getKeys()) {
      final String? value = await read(key);
      if (value != null) {
        values[key] = value;
      }
    }
    return values;
  }

  /// Removes every value this store can name.
  Future<void> deleteAll() => _locked(() async {
    for (final String key in await _readIndex()) {
      await _blobs.delete(_valueName(key));
      _emit(key, SecureStorageChangeKind.deleted);
    }
    await _blobs.delete(_indexName);
  });

  /// Closes [changes]; the stored values are untouched.
  Future<void> dispose() => _changes.close();

  Future<void> _put(String key, String value) =>
      _putBytes(key, Uint8List.fromList(utf8.encode(value)));

  Future<void> _putBytes(String key, Uint8List value) async {
    _validateKey(key);
    await _locked(() async {
      final Uint8List framed = _frame(value);
      try {
        await _blobs.write(_valueName(key), framed);
      } finally {
        zeroSecret(framed);
      }
      final List<String> keys = await _readIndex();
      if (!keys.contains(key)) {
        await _writeIndex(<String>[...keys, key]);
      }
      _emit(key, SecureStorageChangeKind.written);
    });
  }

  /// The stored record without its framing byte, or null when absent.
  Future<Uint8List?> _get(String key) async {
    _validateKey(key);
    final Uint8List? framed = await _blobs.read(_valueName(key));
    if (framed == null) {
      return null;
    }
    if (framed.isEmpty || framed[0] != _recordVersion) {
      await _blobs.delete(_valueName(key));
      zeroSecret(framed);
      return null;
    }
    return Uint8List.sublistView(framed, 1);
  }

  Future<List<String>> _readIndex() async {
    final Uint8List? bytes = await _blobs.read(_indexName);
    if (bytes == null) {
      return <String>[];
    }
    final Object? decoded;
    try {
      decoded = jsonDecode(utf8.decode(bytes));
    } on FormatException {
      return <String>[];
    } finally {
      zeroSecret(bytes);
    }
    if (decoded is! List) {
      return <String>[];
    }
    return decoded.whereType<String>().toList();
  }

  Future<void> _writeIndex(List<String> keys) => _blobs.write(
    _indexName,
    Uint8List.fromList(utf8.encode(jsonEncode(keys))),
  );

  Future<List<String>> _indexWithout(String key) async =>
      (await _readIndex())..remove(key);

  void _emit(String key, SecureStorageChangeKind kind) {
    if (!_changes.isClosed) {
      _changes.add(SecureStorageChange(key, kind));
    }
  }

  /// Runs [body] after every mutation queued before it.
  Future<T> _locked<T>(Future<T> Function() body) {
    final Future<T> result = _tail.then((_) => body());
    _tail = result.then<void>((_) {}, onError: (_) {});
    return result;
  }

  void _validateKey(String key) {
    if (key.isEmpty) {
      throw ArgumentError.value(key, 'key', 'must not be empty');
    }
  }
}

const int _recordVersion = 1;

/// Keeps a value's record and the key index apart, so a key whose text equals
/// the index's name still cannot reach it.
String _valueName(String key) => 'v/$key';
const String _indexName = 'i/index';

Uint8List _frame(Uint8List value) => Uint8List(1 + value.length)
  ..[0] = _recordVersion
  ..setRange(1, value.length + 1, value);
