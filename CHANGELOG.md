## 0.0.1

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
