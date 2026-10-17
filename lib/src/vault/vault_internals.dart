import 'dart:typed_data';

import 'secret_vault.dart';

/// Result codes shared by every backend. Backends never throw across the
/// isolate boundary: they return one of these and the calling isolate turns it
/// into a typed exception, so callers always catch [VaultOperationException]
/// rather than an opaque `RemoteError`.
const int kVaultOk = 0;
const int kVaultNotFound = 1;
const int kVaultUnavailable = 2;
const int kVaultFailure = 3;
const int kVaultAuthRequired = 4;

/// Status, optional payload, raw platform error code, plus an optional
/// non-sensitive [VaultWire.detail] contributed by the backend.
typedef VaultWire = ({int status, Uint8List? data, int osCode, String? detail});

VaultWire vaultOk([Uint8List? data]) =>
    (status: kVaultOk, data: data, osCode: 0, detail: null);

VaultWire vaultNotFound() =>
    (status: kVaultNotFound, data: null, osCode: 0, detail: null);

VaultWire vaultUnavailable({int osCode = 0, String? detail}) =>
    (status: kVaultUnavailable, data: null, osCode: osCode, detail: detail);

VaultWire vaultFailure(int osCode, {String? detail}) =>
    (status: kVaultFailure, data: null, osCode: osCode, detail: detail);

/// The OS will not release the secret until the user authenticates.
VaultWire vaultAuthRequired({int osCode = 0, String? detail}) =>
    (status: kVaultAuthRequired, data: null, osCode: osCode, detail: detail);

/// Throws the exception matching a failed [wire]; succeeds silently otherwise.
void vaultCheckWire(String operation, VaultWire wire) {
  if (wire.status == kVaultUnavailable) {
    throw VaultUnavailableException(
      'Secure storage is unavailable for $operation.'
      '${wire.detail == null ? '' : ' ${wire.detail}'}',
      osCode: wire.osCode,
    );
  }
  if (wire.status == kVaultAuthRequired) {
    throw VaultAuthenticationRequiredException(
      'Secure storage needs the user to authenticate before it will '
      'complete "$operation".'
      '${wire.detail == null ? '' : ' ${wire.detail}'}',
      osCode: wire.osCode,
    );
  }
  if (wire.status == kVaultFailure) {
    throw VaultOperationException(
      'Secure storage failed to $operation.',
      osCode: wire.osCode,
    );
  }
}

/// Largest secret a vault accepts unless its host app raises the cap.
const int kMaxVaultSecretBytes = 1024;

/// Upper bound for a vault created with a larger [SecretVault.maxSecretBytes].
///
/// The four backends all cope with kilobytes; the ceiling exists so a typo
/// cannot ask the Keychain or a keyring daemon to hold a megabyte.
const int kMaxConfigurableVaultSecretBytes = 256 * 1024;

/// Version byte prefixed to every file-backed blob.
const int kVaultBlobVersion = 1;

final RegExp _safeNamePattern = RegExp(r'^[A-Za-z0-9._-]+$');

/// Rejects aliases that are empty, longer than 128 characters, or use anything
/// outside `[A-Za-z0-9._-]`.
void validateAlias(String alias) {
  if (alias.isEmpty) {
    throw ArgumentError.value(alias, 'alias', 'must not be empty');
  }
  if (alias.length > 128) {
    throw ArgumentError.value(alias, 'alias', 'must be at most 128 characters');
  }
  if (!_safeNamePattern.hasMatch(alias)) {
    throw ArgumentError.value(
      alias,
      'alias',
      'may only contain letters, digits, \'.\', \'_\' and \'-\'',
    );
  }
}

/// Namespaces share the alias character rules but are also length capped,
/// because they become part of file names and keychain attributes.
void validateNamespace(String namespace) {
  if (namespace.isEmpty || namespace.length > 64) {
    throw ArgumentError.value(
      namespace,
      'namespace',
      'must be between 1 and 64 characters',
    );
  }
  if (!_safeNamePattern.hasMatch(namespace)) {
    throw ArgumentError.value(
      namespace,
      'namespace',
      'may only contain letters, digits, \'.\', \'_\' and \'-\'',
    );
  }
}

void validateSecret(Uint8List secret, int maxBytes) {
  if (secret.isEmpty) {
    throw ArgumentError.value(secret, 'secret', 'must not be empty');
  }
  if (secret.length > maxBytes) {
    throw ArgumentError.value(
      secret,
      'secret',
      'must be at most $maxBytes bytes, this vault\'s limit',
    );
  }
}

void validateMaxSecretBytes(int maxBytes) {
  if (maxBytes < 1 || maxBytes > kMaxConfigurableVaultSecretBytes) {
    throw ArgumentError.value(
      maxBytes,
      'maxSecretBytes',
      'must be between 1 and $kMaxConfigurableVaultSecretBytes bytes',
    );
  }
}

/// Namespace-prefixed alias, used as the on-disk file name, the Android
/// keystore entry name and part of the Windows DPAPI entropy.
String vaultStorageKey(String namespace, String alias) => '$namespace/$alias';

String vaultFileName(String namespace, String alias) =>
    '$namespace.$alias.vault';

/// Best-effort wipe of a buffer owned by the vault. Never call this on a
/// buffer the caller passed in.
void zeroSecret(Uint8List? bytes) {
  if (bytes == null) {
    return;
  }
  bytes.fillRange(0, bytes.lengthInBytes, 0);
}
