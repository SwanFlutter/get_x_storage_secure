import 'secret_vault.dart';
import 'vault_options.dart';
import 'vault_factory_stub.dart'
    if (dart.library.io) 'vault_factory_native.dart'
    as native;

/// Creates the vault backed by the operating system's secret store.
///
/// * Android: `AndroidKeyStore` (StrongBox when available) with the encrypted
///   blob in `noBackupFilesDir`.
/// * iOS / macOS: the Keychain, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
///   unless [VaultOptions.apple] says otherwise.
/// * Windows: DPAPI per-user with per-alias entropy, blob in local app-data.
/// * Linux: `libsecret` / Secret Service over D-Bus.
///
/// [namespace] defaults to the package name and is combined with every alias so
/// that several apps or containers sharing one store cannot read each other.
/// [options] carries the per-platform settings and the size ceiling of a single
/// write; a backend ignores the options that belong to another platform.
///
/// Importing this and creating the vault touches no native API: the first call
/// does, and it runs on a worker isolate.
///
/// Throws [UnsupportedError] on the web, which has no OS-backed secret store.
SecretVault createPlatformVault({
  String namespace = kDefaultVaultNamespace,
  VaultOptions options = const VaultOptions(),
}) => native.createVault(namespace, options);
