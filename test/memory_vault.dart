import 'dart:typed_data';

import 'package:get_x_storage_secure/src/vault/secret_vault.dart';
import 'package:get_x_storage_secure/src/vault/vault_internals.dart';

/// A [SecretVault] that keeps entries in a map, for tests that need the layers
/// above it without touching the real keystore.
class MemorySecretVault implements SecretVault {
  MemorySecretVault({this.maxSecretBytes = kMaxVaultSecretBytes});

  @override
  final int maxSecretBytes;

  final Map<String, Uint8List> _entries = <String, Uint8List>{};

  /// The entries written through the fake, so tests can assert on namespacing
  /// and on how a value was split.
  Map<String, Uint8List> get entries =>
      Map<String, Uint8List>.unmodifiable(_entries);

  @override
  Future<void> write(String alias, Uint8List secret) async {
    validateAlias(alias);
    validateSecret(secret, maxSecretBytes);
    _entries[alias] = Uint8List.fromList(secret);
  }

  @override
  Future<Uint8List?> read(String alias) async {
    validateAlias(alias);
    final Uint8List? stored = _entries[alias];
    return stored == null ? null : Uint8List.fromList(stored);
  }

  @override
  Future<void> delete(String alias) async {
    validateAlias(alias);
    _entries.remove(alias);
  }

  @override
  Future<bool> contains(String alias) async {
    validateAlias(alias);
    return _entries.containsKey(alias);
  }
}
