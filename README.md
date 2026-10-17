# get_x_storage_secure

Stores an app's secrets in the operating system's own secret store — the
Android keystore, Windows DPAPI, the iOS/macOS Keychain, libsecret on Linux —
rather than in a file the app encrypted itself. The OS holds the key, the bytes
on disk are never plaintext, and the app can extract no more than the OS allows.

Two layers sit on top of each other:

| Layer | Use it for |
| --- | --- |
| `SecretVault` | one small OS-protected secret per alias: a master key, a signing key |
| `SecureStorage` | ordinary string key/value pairs, of any length, listable and deletable |

If you only need to cache tokens and settings, use `SecureStorage`. Keep
`SecretVault` for a key your own crypto uses, so that the key never has to be
turned into a string.

## SecretVault

```dart
final SecretVault vault = createPlatformVault();
await vault.write('master_key', secret);          // Uint8List
final Uint8List? recovered = await vault.read('master_key');
final bool present = await vault.contains('master_key');
await vault.delete('master_key');                 // a missing alias is a no-op
```

* `read` answers `null` when the alias is absent **or** the protected data
  became unrecoverable (key invalidated, another device restored a backup).
  There is no recovery path to report, so this is never an exception.
* Aliases match `[A-Za-z0-9._-]{1,128}`; a secret is 1 KB by default, raised per
  backend with `VaultOptions(maxSecretBytes: …)` up to 256 KB.
* A facility that cannot be used at all throws `VaultUnavailableException`;
  anything else that goes wrong throws `VaultOperationException` with the
  numeric OS code. No message, `toString()` or log line on these paths can carry
  secret bytes, and a secret waiting on the user throws
  `VaultAuthenticationRequiredException` instead.

## SecureStorage

```dart
final SecureStorage store = SecureStorage();
await store.write('session_token', token);
final String? token = await store.read('session_token');
final List<String> keys = await store.getKeys();
final Map<String, String> all = await store.readAll();
await store.delete('session_token');              // a missing key is a no-op
await store.deleteAll();
store.changes.listen((c) => render(c));           // names the key, never the value
```

What that buys over the raw vault:

* **Any key text.** Keys are hashed to their vault alias, so spaces, Persian,
  emoji, and `/` are all legal, and two keys differing only in case stay
  distinct even on a backend whose native names are case-insensitive.
* **Any value length.** A value longer than one OS write is split across vault
  entries and reassembled on read; `readBytes`/`writeBytes` keep binary values
  binary.
* **Listing.** `getKeys`, `readAll` and `deleteAll` work because the key names
  travel through a vault entry themselves — the keystore, DPAPI and the Keychain
  offer no way to enumerate what they hold.

Options are per platform, in the spirit of `IOSOptions`/`AndroidOptions`:

```dart
final SecureStorage store = SecureStorage(
  namespace: 'my_app',
  options: VaultOptions(
    maxSecretBytes: 8 * 1024, // each chunk pushed into the vault
    apple: const AppleVaultOptions(
      accessibility: AppleAccessibility.afterFirstUnlockThisDeviceOnly,
      authentication: AppleAuthentication.biometryCurrentSet,
      authenticationPrompt: 'Unlock the saved token',
    ),
    android: const AndroidVaultOptions(
      requireUserAuthentication: true,
      authenticationTimeoutSeconds: 30,
    ),
    windows: const WindowsVaultOptions(),
  ),
);
```

The authentication gates make a secret unreadable until the user passes biometrics
or the device credential: Android keys carry `setUserAuthenticationParameters`,
Apple items carry a `SecAccessControl`. Either way an unreadable secret raises
`VaultAuthenticationRequiredException`, and the app re-prompts and retries.
Web has no OS secret store, so both layers throw `UnsupportedError` there rather
than fall back to plain `localStorage`.

## Guarantees that hold everywhere here

* Nothing happens at import time. Creating a vault opens no library and calls no
  native API; the first read or write does, so app startup pays nothing.
* Every call runs on its own isolate (`Isolate.run`), because a keystore, DPAPI
  or a D-Bus round trip can block for a while. No global mutable state exists
  except a lazily opened library handle.
* A value is only ever a plaintext `String` or `Uint8List` in the Dart heap: the
  buffers the storage layer builds around it are zeroed as soon as the OS has
  the bytes. Dart strings are immutable, so for a value that must not outlive
  the object use `writeBytes` with a buffer you zero yourself.

## Android backup rules

Auto Backup restores files but never keystore keys, so a migrated install would
meet blobs it cannot open. The blobs already live in `noBackupFilesDir`, outside
Auto Backup's default set; state it anyway so later files there cannot slip into
a backup:

```xml
<!-- android/app/src/main/AndroidManifest.xml -->
<application
    android:fullBackupContent="@xml/backup_rules"
    android:dataExtractionRules="@xml/data_extraction_rules">

<!-- res/xml/backup_rules.xml (Android 11 and below) -->
<full-backup-content>
    <exclude domain="noBackupFiles" path="." />
</full-backup-content>

<!-- res/xml/data_extraction_rules.xml (Android 12 and above) -->
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="noBackupFiles" path="." />
    </cloud-backup>
    <device-transfer>
        <exclude domain="noBackupFiles" path="." />
    </device-transfer>
</data-extraction-rules>
```

## Structure

* `lib/src/vault/` — the `SecretVault` interface, `VaultOptions`, and one
  backend per OS: `android_vault.dart` (package:jni into
  `android/src/main/kotlin/…/VaultKeyStore.kt`), `windows_vault.dart` (DPAPI),
  `apple_vault.dart` (Security framework), `linux_vault.dart` (libsecret).
* `lib/src/storage/` — `secure_storage.dart` (keys, index, chunking) over
  `blob_store.dart` (a byte record split into vault-sized parts).
* `src/`, plus the per-platform `CMakeLists.txt` and podspec — the template's
  native build graph. The Dart code does not call into it; the plugin
  declarations in `pubspec.yaml` still expect those projects to build, so the
  files stay.
* `example/` — a two-tab app: the vault page holds a 32-byte master key, the
  key-value page drives `SecureStorage`.

## Testing

```sh
dart analyze lib test tool example
flutter test                                   # contract tests; non-native suites skip
cd example
flutter test integration_test -d windows       # demo + both contracts on DPAPI
flutter test integration_test -d <device>      # on a phone with the screen awake
```

`test/vault_contract.dart` and `test/secure_storage_contract.dart` hold the
expectations once and each backend runs them, so a new platform is judged by the
same list. `tool/jnigen.dart` regenerates the Android bindings after the Kotlin
helper changes; `NOTES.md` covers that, the per-platform assumptions, and the
OS minimums.
