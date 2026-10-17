import 'dart:io';

import 'android_vault.dart';
import 'apple_vault.dart';
import 'linux_vault.dart';
import 'secret_vault.dart';
import 'vault_options.dart';
import 'windows_vault.dart';

/// Selection happens here rather than in the constructor of a single class so
/// that no backend's FFI symbols are resolved on a platform that lacks them.
///
/// Each backend validates and applies only its own options, so one [VaultOptions]
/// value can be passed everywhere.
SecretVault createVault(String namespace, VaultOptions options) {
  if (Platform.isAndroid) {
    return AndroidSecretVault(
      namespace: namespace,
      options: options.android,
      maxSecretBytes: options.maxSecretBytes,
    );
  }
  if (Platform.isIOS || Platform.isMacOS) {
    return AppleSecretVault(
      namespace: namespace,
      options: options.apple,
      maxSecretBytes: options.maxSecretBytes,
    );
  }
  if (Platform.isWindows) {
    return WindowsSecretVault(
      namespace: namespace,
      directory: options.windows.directory,
      maxSecretBytes: options.maxSecretBytes,
    );
  }
  if (Platform.isLinux) {
    return LinuxSecretVault(
      namespace: namespace,
      maxSecretBytes: options.maxSecretBytes,
    );
  }
  throw UnsupportedError(
    'get_x_storage_secure has no secret vault for '
    '${Platform.operatingSystem}.',
  );
}
