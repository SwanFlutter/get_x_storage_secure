## 1.0.0

* `SecretVault`: one OS-protected secret per alias, in AndroidKeyStore, Windows
  DPAPI, the iOS/macOS Keychain, or libsecret on Linux. Reading an absent or
  unrecoverable secret answers `null`; anything else is a typed exception that
  carries an OS code and never a secret.
* `SecureStorage`: the key/value layer apps expect on top of it — any key text,
  values longer than one OS write, `getKeys`/`readAll`/`deleteAll` through an
  encrypted index, and a change stream that names the key but not the value.
* `VaultOptions` per platform: secret size cap, Keychain accessibility, iCloud
  sync and access groups on Apple, biometric or device-credential gating on
  Android and Apple, blob directory on Windows.
* Nothing native happens at import or construction time, and every call runs on
  its own isolate, so a slow keystore never blocks the UI.
* `example/` drives both layers from one two-tab app, and one behavioural
  contract per layer (`test/vault_contract.dart`,
  `test/secure_storage_contract.dart`) runs against it on a real device — 11 and
  17 cases on Android and on Windows DPAPI, plus a memory vault in `flutter test`
  so chunking and the index stay covered with no keyring present.
* Not covered by this release: the iOS/macOS and Linux backends are written and
  analyzer-clean but have never been run, the authentication gates are untested
  on hardware, and the web throws `UnsupportedError` because browsers expose no
  OS keystore.
