import 'secret_vault.dart';
import 'vault_options.dart';

/// Web has no OS-backed secret store, and `dart:ffi`/`dart:io` are unavailable
/// there. This stub exists only so that importing the package does not break a
/// web build; [createPlatformVault] still reports the real failure.
SecretVault createVault(
  String namespace,
  VaultOptions options,
) => throw UnsupportedError(
  'get_x_storage_secure has no secret vault for the web. '
  'Secure storage needs an operating-system keystore, which browsers do not '
  'expose to Dart. Build for Android, iOS, macOS, Windows or Linux.',
);
