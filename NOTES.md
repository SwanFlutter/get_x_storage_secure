# Secrets — assumptions, limits, and what was verified

Two layers, one invariant: the operating system holds the key.

* `lib/src/vault/`, `android/src/main/kotlin/`, `android/consumer-rules.pro`,
  `tool/jnigen.dart`, `test/vault_*` — the OS-protected secret store: one small
  secret per alias (a master key, a signing key).
* `lib/src/storage/`, `test/secure_storage_*` — `SecureStorage` over it: text
  keys of any name, values of any length, and the encrypted index that makes
  them listable.

Neither layer is an encryption library for arbitrary data, and neither writes a
plaintext byte to disk.

## Public surface

```dart
final SecretVault vault = createPlatformVault();          // namespace defaults
await vault.write('master_key', Uint8List(32));
final Uint8List? key = await vault.read('master_key');    // null when gone
await vault.delete('master_key');                          // missing is a no-op
final bool present = await vault.contains('master_key');

final SecureStorage store = SecureStorage(namespace: 'my_app');
await store.write('session_token', '…');                   // any key, any length
final Map<String, String> all = await store.readAll();
await store.deleteAll();
```

Vault aliases match `[A-Za-z0-9._-]{1,128}`; a secret is capped at 1 KB
(`kMaxVaultSecretBytes`) and `VaultOptions(maxSecretBytes:)` raises that per
backend up to `kMaxConfigurableVaultSecretBytes` (256 KB). Both layers validate
before a native call happens. `SecureStorage` keys are arbitrary text because
each one is hashed to its alias — see "Storage layer" below.

Failures are `VaultUnavailableException` (the facility cannot be used at all),
`VaultOperationException` (carries a numeric OS code), or
`VaultAuthenticationRequiredException` (the secret is intact but gated on the
user). None of them can carry a secret: backends hand the caller a numeric code
and a fixed hint string, and the payload crosses the isolate boundary only
inside `read()`'s return value.


## How it is structured

`vault_internals.dart` defines `VaultWire`, a record of
`(status, data, osCode, detail)` that every backend returns from its worker
isolate. Only strings, ints and byte lists cross `Isolate.run`, so a native
failure becomes a typed Dart exception *on the calling isolate* rather than an
opaque `RemoteError`. `createPlatformVault()` uses a conditional import so the
package still compiles for the web, where it throws `UnsupportedError`.

Importing the package or constructing a vault touches no native API. Library
handles (`DynamicLibrary`, JNI class lookups) are `final` top-levels with
initialisers, which Dart evaluates lazily and per isolate — that is the only
global state, and heavy work (Keystore, DPAPI, D-Bus, SecItem) runs inside
`Isolate.run` so the UI isolate never blocks.

## Storage layer

`SecureStorage` adds nothing to what the OS protects: every value and the key
index itself go through `SecretVault`, so a data key never exists in the Dart
heap. What it adds is the shape apps expect from a key/value store.

* **Names.** `BlobStore` maps a name to `sha256(name)` hex, which satisfies the
  vault alias rule whatever the caller passed and keeps `Token` and `token`
  apart — AndroidKeyStore names are case-insensitive, so a readable store cannot
  be built on the raw key. `SecureStorage` prefixes `v/` to a key's name and
  keeps the index under `i/index`, so a key literally called `index` still
  cannot reach it.
* **Length.** A record is `[version][payload]`, split into
  `maxSecretBytes`-sized parts plus a meta record holding the part size and the
  total length, from which the part count follows. The meta record is written
  last, so a crash mid-write leaves the old record readable rather than a
  half-written new one, and a meta whose parts are missing reads back as absent
  and purges the record.
* **Listing.** `{name, name, …}` is stored as a JSON array in one vault entry,
  so `getKeys`, `readAll` and `deleteAll` work on backends that cannot enumerate.
  A damaged index reads back empty, which costs names, not values.
* **Ordering.** Mutations chain through one `Future` per instance, so two
  concurrent writes cannot each read the index and overwrite the other's copy.
  Reads take no lock and stay parallel.
* **Zeroing.** Framing and chunk buffers are `zeroSecret`-ed once the vault has
  the bytes; an immutable `String` argument is still the caller's copy and outlives
  the call, which is why `writeBytes`/`readBytes` exist.

## Platform notes

### Android — API 23+
Non-exportable AES-256-GCM keys in AndroidKeyStore, one per alias, with the
blob in `noBackupFilesDir`; the alias is bound as additional authenticated
data, so a blob cannot be replayed under another alias. StrongBox is tried
first on API 28+ and the TEE/software key is used when
`StrongBoxUnavailableException` says the chip is absent. A key destroyed by a
lock-screen change or factory reset (`KeyPermanentlyInvalidatedException`,
`AEADBadTagException`, `UnrecoverableKeyException`, or a KeyStore entry that
vanished while the file stayed) deletes both the blob and the entry and `read`
returns `null` — there is no recovery path to report.

`VaultKeyStore.kt` stays free of business logic on purpose: it takes the file
name, the KeyStore alias and the AAD string from Dart, and returns a framed
status (`[status][errorCode little-endian int16][payload]`) instead of
throwing. Reaching it by JNI means R8 must not rename it, so
`android/consumer-rules.pro` keeps it.

Calling it is safe off the UI isolate: `androidApplicationContext` is a plain
static JNI call rather than a platform channel, dartjni attaches each thread it
is used from, and `JClass.forName` resolves through the application ClassLoader
that `jni_flutter` installs — which is what the keep rule above protects. The
vault takes the context inside the worker isolate and releases every local
reference it creates.

**Auto Backup restores files but not Keystore keys.** Without an exclusion, a
restored install gets blobs whose keys no longer exist, and every `read`
silently returns `null` the first time it is called. Apps should exclude the
vault files (`noBackupFilesDir` is already outside Auto Backup's default set,
but explicit rules are safer once other files are added):

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

AndroidKeyStore aliases are case-insensitive, so the raw vault cannot promise
that `Token` and `token` are two secrets; `SecureStorage` sidesteps that by
storing under a hash of the key.

`AndroidVaultOptions(requireUserAuthentication: true)` makes the per-alias key
usable only after the user has authenticated within
`authenticationTimeoutSeconds` (API 30+ uses `setUserAuthenticationParameters`,
older releases the validity-duration call). No BiometricPrompt is launched from
the library — that needs an Activity, and this plugin deliberately has no
method channel — so a gated read while the window is closed answers
`VaultAuthenticationRequiredException` and leaves the secret alone. The app
unlocks the device or runs its own prompt and calls again. The Kotlin helper
recognises that state by walking the cause chain for the
`KeyPerAliveException`/`KeyPermissionException`/`KeyUserNotAuthenticatedException`/
`BadCredentialException` family rather than by matching a message string.

### iOS 15+ / macOS — shared code path
`kSecClassGenericPassword` with `kSecAttrService = namespace`,
`kSecAttrAccount = alias` and, by default,
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` plus
`kSecAttrSynchronizable = false`; macOS additionally sets
`kSecUseDataProtectionKeychain` to avoid the legacy file-backed keychain.
`AppleVaultOptions` changes the class (`afterFirstUnlock` for something that
must survive a reboot), opts into iCloud sync (rejected together with a
`ThisDeviceOnly` class), sets `kSecAttrAccessGroup`, or gates the item on
`SecAccessControlCreateWithFlags` with `kSecAccessControlUserPresence` /
`kSecAccessControlBiometryCurrentSet` — in which case `kSecAttrAccessControl`
replaces `kSecAttrAccessible` (the two are mutually exclusive) and every read
carries `kSecUseOperationPrompt`, whose text must be localised in the app.
`write` is `SecItemAdd` with `SecItemUpdate` on `errSecDuplicateItem`;
`errSecItemNotFound` becomes `null`. `errSecInteractionNotAllowed` (-25308, the
device is locked) and `errSecAuthFailed` (-25293, the user did not or could not
authenticate) become `VaultAuthenticationRequiredException` with the OSStatus
attached, so a caller retries after unlock instead of reading the secret as gone.
No entitlements are needed for a single app; to share a vault between apps or
extensions, add the `keychain-access-groups` entitlement and pass the same group
as `AppleVaultOptions.accessGroup`.

CoreFoundation objects are created through a `_CfBag` that retains each one and
releases them in reverse order, and the native buffer behind a returned `CFData`
is zeroed before `CFRelease`.

Bindings are hand-written Dart FFI rather than ffigen output: ffigen needs the
macOS SDK headers and a clang it cannot run on this host.

### Windows
DPAPI (`CryptProtectData` / `CryptUnprotectData`) with
`CRYPTPROTECT_UI_FORBIDDEN`, user scope, and `"$namespace/$alias"` as
`optionalEntropy`, so a blob is bound to this user, this machine and this alias.
The protected blob is written as `[version][dpapi blob]` next to a temp file
that is moved over the target with `MoveFileEx` and
`MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`. Every `DATA_BLOB` output is
zeroed and released with `LocalFree`, and the plaintext staging buffer is zeroed
after use.

The directory is `%LOCALAPPDATA%\<namespace>\secure_vault`, *not*
`path_provider`'s application-support directory: path_provider returns `%APPDATA%`
(Roaming) on Windows, and DPAPI master keys are per-machine, so a roaming
profile would carry blobs that can never be decrypted. A Windows-only keyring
would be the alternative; keeping the blob local loses nothing because DPAPI
already binds it to the machine. `WindowsVaultOptions(directory: ...)` — or
`WindowsSecretVault(directory: ...)` — overrides the location for tests.

DPAPI is user scope: it protects a blob from another account on the same machine
and from a copied file, not from code running as this user. That is the same
threat model the platform's own credential store has; a machine-wide or
TPM-bound secret needs a different facility.

A blob that no longer decrypts — the account is gone, the machine was reimaged,
the profile roamed — is reported as absent, because `null` is the only honest
answer. A bad framing version byte is a `VaultOperationException`.

### Linux
`libsecret-1.so.0` plus `libglib-2.0.so.0`, opened on first use. Item attributes
come from a `SecretSchema` with `namespace` and `alias` string attributes.

`secret_password_store_sync`, `secret_password_lookup_sync` and
`secret_password_clear_sync` take attributes as C varargs, which `dart:ffi`
cannot call, so the documented non-variadic `*_v_sync` variants are used with a
`GHashTable` (built with `g_str_hash`/`g_str_equal`/`g_free` and `g_strdup`'d
keys, so ownership stays inside GLib). `SECRET_COLLECTION_DEFAULT` is a macro
over `_secret_collection_default()`, which libsecret marks internal and hides,
so `NULL` is passed instead — `secret_service_store()` documents `NULL` as "the
default collection". `secret_service_get_sync` is called first so a machine
without a keyring daemon produces `VaultUnavailableException` with install
instructions rather than a per-operation failure.

Because the Secret Service stores text, the secret reaches the daemon as a
base64 `String`; Dart strings are immutable, so that copy cannot be wiped (the
native buffer it was read from *is* zeroed before `secret_password_free`).
libsecret has no non-variadic attribute-only search, so `contains()` performs a
real lookup and discards the value.

## Verification status

| Platform | What was checked here |
| --- | --- |
| Windows | `flutter test` in the package — 66 pass, 34 skip (the Android, Apple and Linux groups are off-platform): the vault contract against real DPAPI (read-back, overwrite, replay under another alias, tamper detection, the 128-char alias limit, a raised cap), the storage contract over a memory vault and over real DPAPI, and the option validation. `flutter build windows` in `example/` succeeds, and `flutter test integration_test -d windows` runs all three files: the two-tab demo tap-through, the vault contract, and the storage contract against DPAPI with a fresh namespace per case. |
| Android | `flutter build apk --debug` succeeds with the `io.github.swanflutter` package name. On a Xperia XQ-AD51 (API 28, arm64) all three `example/integration_test` files pass through `flutter test integration_test -d <device>`: the vault contract (11 cases) against the real AndroidKeyStore, the storage contract (17 cases) — including keys that differ only in case, values split across parts, and 20 concurrent writes — and the two-tab demo tap-through. That also proves the JNI call works from a worker isolate. Being API 28, the runs go through the StrongBox attempt, so the `StrongBoxUnavailableException` fallback is covered whichever way the chip answered. **Not yet exercised on-device:** the `requireUserAuthentication` gate, which needs a secured lock screen and a real prompt, and `readAll` on a device with a lock-screen change after writing. |
| iOS, macOS | Analyzer-clean FFI only. Cannot be compiled or run on a Windows host, so the `SecAccessControl` gate and the sync rules are unverified. |
| Linux | Analyzer-clean FFI only. No libsecret and no Secret Service on this host. |
| Web | Both layers compile and answer `UnsupportedError` through the conditional-import stub; `dart analyze` passes for the web target. |

## Running the tests

`test/*_test.dart` skips its whole group when the platform facility is missing,
so a host without a keyring or an Apple SDK stays green; `flutter test` on
Windows therefore runs the DPAPI and storage suites plus 34 documented skips.
`test/linux_vault_test.dart` is additionally opt-in with `GXS_TEST_LIBSECRET=1`,
because a stored secret would otherwise be written into the developer's own
keyring.

`test/memory_vault.dart` is the third backend the storage contract runs against:
a 64-byte cap that forces nearly every record through the split path, an
`entries` map a test can reach into to delete one part, and nothing OS-specific.
That is how the chunking, the index and the purge stay covered on a host with no
keyring at all.

`example/integration_test/` holds the three runs that need a built app: the demo
tap-through, the vault contract applied to `createPlatformVault()`, and the
storage contract applied to `SecureStorage()` — each case getting its own
namespace so a real store starts empty, and cleaned up in `tearDownAll`. All
three work on any device or host, so the same files cover Android phones and
desktop. `test/vault_contract.dart` and `test/secure_storage_contract.dart` are
imported from `example` by relative path; keeping one contract definition avoids
a second copy drifting.

## Package notes

* The Android package and the Linux application id are
  `io.github.swanflutter.get_x_storage_secure`, not the template's
  `com.example`.
* `src/` and the per-platform native build files still hold the template's tiny
  C library. Nothing in `lib/` calls it; `pubspec.yaml` declares `ffiPlugin:
  true` for each platform, and those build graphs (`android/build.gradle` runs
  CMake over `../src/CMakeLists.txt`) expect the project to exist. Deleting it
  is a separate change from deleting the demo, and both the Windows and Android
  builds were verified with it in place.
* `ffigen` is gone from the dependencies and `ffigen.yaml` is deleted: no
  binding is generated any more. Android bindings come from `tool/jnigen.dart`,
  the other backends are hand-written.
* `/android/.cxx/` and `**/local.properties` are gitignored. `local.properties`
  must stay on disk — `tool/jnigen.dart` reads `sdk.dir` out of it — but it is
  this machine's SDK path and has no business in a repository or a zip.

Two build-environment notes for this machine: Gradle needs a JDK no newer than
21 — with `C:\Program Files\Java\jdk-26.0.1` as `JAVA_HOME`, AGP's `jlink` step
on `core-for-system-modules.jar` fails for the `:jni` module. And tests must run
under `flutter test`, not `dart test`, because `jni_flutter` pulls in Flutter.
`integration_test` asks for open-ended `androidx.test` versions, so its first
Gradle run needs the network; a transient metadata failure there reports
"no versions available" and simply succeeds on retry.

Flutter also warns that this plugin applies the Kotlin Gradle Plugin by hand.
Android's vault needs Kotlin, and plugin modules cannot use the newer
"Built-in Kotlin" mode yet, so `android/build.gradle` keeps `apply plugin:
"kotlin-android"`; revisit it if the warning ever becomes an error.

## Regenerating bindings

```sh
cd example/android && ./gradlew :get_x_storage_secure:compileDebugKotlin
dart run tool/jnigen.dart          # writes lib/src/vault/android_bindings.dart
```

`tool/jnigen.dart` replaces `jnigen.yaml`: the YAML format is deprecated in
`jnigen` 1.0 and the Dart script is the supported configuration.
