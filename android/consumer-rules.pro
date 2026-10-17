# VaultKeyStore is looked up by class name over JNI, so shrinking or obfuscating
# it would break the vault at runtime rather than at build time.
-keep class io.github.swanflutter.get_x_storage_secure.vault.** { *; }
