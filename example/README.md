# get_x_storage_secure_example

Two tabs, one per layer of the plugin.

* **Vault** — `createPlatformVault()`. Writes a 32-byte stand-in for a master
  key, reads it back, checks for it, deletes it. The log says what happened,
  never what the bytes were.
* **Key-value** — `SecureStorage()`. Type any key and any value: save it, read
  it back, list every key, delete one or all. Each press also appears as a
  `change ->` line from `SecureStorage.changes`.

The buttons are the whole app on purpose: no configuration, no console, so the
same file can be driven by an integration test on a phone.

```sh
flutter run
flutter test integration_test -d windows    # desktop
flutter test integration_test -d <device>   # phone, screen awake
```

The three files under `integration_test/` tap through this app and then run the
package's shared vault and storage contracts against the real OS store.
