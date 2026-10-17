import 'dart:typed_data';

/// Stores a small secret so that it is protected by the operating system and
/// never written to disk in plaintext.
abstract interface class SecretVault {
  /// Largest secret [write] accepts on this backend, in bytes.
  ///
  /// Defaults to `kMaxVaultSecretBytes` (1 KB); a vault may be created with a
  /// bigger value up to `kMaxConfigurableVaultSecretBytes` (256 KB).
  int get maxSecretBytes;

  /// Throws [VaultUnavailableException] if the OS facility cannot be used.
  Future<void> write(String alias, Uint8List secret);

  /// Returns null if alias does not exist or the protected data became
  /// unrecoverable (e.g. key invalidated). Never throws for "not found".
  ///
  /// A secret gated on user authentication throws
  /// [VaultAuthenticationRequiredException] instead: it is neither missing nor
  /// lost, so a retry after authenticating can still succeed.
  Future<Uint8List?> read(String alias);

  Future<void> delete(String alias);

  Future<bool> contains(String alias);
}

/// Thrown when the platform secret store is missing entirely or refuses to be
/// used at all (no Keychain daemon, no Android keystore provider, `libsecret`
/// not installed, no Secret Service on D-Bus).
class VaultUnavailableException implements Exception {
  const VaultUnavailableException(this.message, {this.osCode});

  final String message;

  /// Raw platform status, when the failure came from a call that reported one.
  final int? osCode;

  @override
  String toString() =>
      'VaultUnavailableException: $message${osCode == null ? '' : ' (osCode: $osCode)'}';
}

/// Thrown when a single operation failed on an otherwise usable store.
class VaultOperationException implements Exception {
  const VaultOperationException(this.message, {required this.osCode});

  final String message;

  /// Raw platform status (OSStatus, `GetLastError`, JNI exception class name
  /// hash or `GError.code`) so callers can branch without seeing secrets.
  final int osCode;

  @override
  String toString() => 'VaultOperationException: $message (osCode: $osCode)';
}

/// Thrown when a secret is protected by user authentication and the OS has not
/// seen any recently: the caller can authenticate (device unlock, biometric
/// prompt) and retry the same call.
///
/// This is deliberately not a [VaultOperationException]: the secret is intact,
/// only its release is gated.
class VaultAuthenticationRequiredException implements Exception {
  const VaultAuthenticationRequiredException(this.message, {this.osCode});

  final String message;

  /// Raw platform status, when the failure came from a call that reported one.
  final int? osCode;

  @override
  String toString() =>
      'VaultAuthenticationRequiredException: $message'
      '${osCode == null ? '' : ' (osCode: $osCode)'}';
}

/// Namespace used when the caller does not supply one.
const String kDefaultVaultNamespace = 'get_x_storage_secure';
