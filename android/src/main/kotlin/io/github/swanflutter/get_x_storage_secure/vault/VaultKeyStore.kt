package io.github.swanflutter.get_x_storage_secure.vault

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

// Wire status codes shared with lib/src/vault/vault_internals.dart.
private const val OK = 0
private const val NOT_FOUND = 1
private const val UNAVAILABLE = 2
private const val FAILURE = 3
private const val AUTH_REQUIRED = 4

// Reported back as the exception's platform error code; never a secret.
private const val E_IO = 200
private const val E_SECURITY = 201
private const val E_BAD_BLOB = 202
private const val E_KEYSTORE = 300

/**
 * Class names of the exceptions AndroidKeyStore throws when a key is bound to
 * recent user authentication and the user has not provided it. They are looked
 * up by name because they live in `android.security`, whose API levels predate
 * some of the versions this helper supports.
 */
private val AUTH_PENDING = setOf(
    "android.security.KeyPerAliveException",
    "android.security.KeyPermissionException",
    "android.security.KeyExpiredException",
    "android.hardware.biometrics.BadCredentialException",
    "android.security.KeyUserNotAuthenticatedException",
)

private fun needsAuthentication(e: Throwable): Boolean {
    var cause: Throwable? = e
    while (cause != null) {
        if (AUTH_PENDING.contains(cause.javaClass.name)) return true
        cause = cause.cause
    }
    return false
}

/**
 * Non-exportable AES-256-GCM keys in AndroidKeyStore, one per vault alias, with
 * the ciphertext kept in `noBackupFilesDir`.
 *
 * Every method returns a frame instead of throwing:
 * `[status: byte][errorCode: little-endian int16][payload]`. A key destroyed by
 * a lock-screen or factory reset (the common `read` failure) removes the blob
 * and the KeyStore entry and reports `NOT_FOUND`, because the app cannot recover
 * it and `SecretVault.read` is specified to answer `null`.
 *
 * [write] can bind its key to recent user authentication. While that window is
 * closed, [write] and [read] report `AUTH_REQUIRED` and leave the blob alone:
 * the secret is intact, only its use is gated.
 *
 * Auto Backup restores files but not AndroidKeyStore keys, so a restored install
 * finds blobs whose keys are gone. `dataExtractionRules` / `fullBackupContent`
 * must exclude these files; see NOTES.md in the vault directory.
 */
object VaultKeyStore {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val VERSION: Byte = 1
    private const val IV_SIZE = 12
    private const val TAG_BITS = 128

    private fun frame(status: Int, code: Int = 0, payload: ByteArray? = null): ByteArray =
        byteArrayOf(status.toByte(), code.toByte(), (code shr 8).toByte()) + (payload ?: ByteArray(0))

    private fun file(context: Context, name: String): File = File(context.noBackupFilesDir, name)

    private fun keystore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun newKey(
        alias: String,
        strongBox: Boolean,
        requireAuth: Boolean,
        authTimeoutSeconds: Int,
    ): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .apply {
                if (requireAuth) {
                    setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(
                            authTimeoutSeconds,
                            KeyProperties.AUTH_BIOMETRIC_STRONG or
                                KeyProperties.AUTH_DEVICE_CREDENTIAL,
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(
                            authTimeoutSeconds,
                        )
                    }
                } else {
                    setUserAuthenticationRequired(false)
                }
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            .apply { init(spec) }
            .generateKey()
    }

    /** StrongBox where the device has one, TEE/beanpole software keys otherwise. */
    private fun generateKey(
        alias: String,
        requireAuth: Boolean,
        authTimeoutSeconds: Int,
    ): SecretKey = try {
        newKey(alias, true, requireAuth, authTimeoutSeconds)
    } catch (e: StrongBoxUnavailableException) {
        deleteQuietly(alias)
        newKey(alias, false, requireAuth, authTimeoutSeconds)
    }

    private fun existingKey(alias: String): SecretKey? {
        val store = keystore()
        return if (store.containsAlias(alias)) {
            store.getKey(alias, null) as SecretKey?
        } else {
            null
        }
    }

    private fun deleteQuietly(alias: String) {
        try {
            keystore().deleteEntry(alias)
        } catch (e: GeneralSecurityException) {
            // The entry is already unusable; nothing else to clean up.
        }
    }

    private fun purge(stored: File, alias: String) {
        if (stored.exists() && !stored.delete() && stored.exists()) {
            throw IOException("could not remove ${stored.name}")
        }
        deleteQuietly(alias)
    }

    private fun replaceFile(target: File, content: ByteArray) {
        val temp = File(target.parentFile, "${target.name}.${System.nanoTime()}.tmp")
        try {
            temp.outputStream().use {
                it.write(content)
                it.flush()
                it.fd.sync()
            }
            if (!temp.renameTo(target)) throw IOException("could not publish ${target.name}")
        } finally {
            temp.delete()
        }
    }

    @JvmStatic
    fun write(
        context: Context,
        fileName: String,
        keyAlias: String,
        aad: String,
        secret: ByteArray,
        requireAuth: Boolean,
        authTimeoutSeconds: Int,
    ): ByteArray = try {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            generateKey(keyAlias, requireAuth, authTimeoutSeconds),
        )
        cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        val body = cipher.doFinal(secret)
        val iv = cipher.iv
        if (iv.size != IV_SIZE) throw GeneralSecurityException("unexpected IV length")
        val blob = ByteArray(1 + IV_SIZE + body.size)
        blob[0] = VERSION
        iv.copyInto(blob, 1)
        body.copyInto(blob, 1 + IV_SIZE)
        replaceFile(file(context, fileName), blob)
        frame(OK)
    } catch (e: KeyStoreException) {
        frame(UNAVAILABLE, E_KEYSTORE)
    } catch (e: GeneralSecurityException) {
        if (needsAuthentication(e)) frame(AUTH_REQUIRED) else frame(FAILURE, E_SECURITY)
    } catch (e: IOException) {
        frame(FAILURE, E_IO)
    }

    @JvmStatic
    fun read(
        context: Context,
        fileName: String,
        keyAlias: String,
        aad: String,
    ): ByteArray {
        val stored = file(context, fileName)
        if (!stored.exists()) return frame(NOT_FOUND)
        return try {
            val blob = stored.readBytes()
            if (blob.size <= 1 + IV_SIZE || blob[0] != VERSION) {
                return frame(FAILURE, E_BAD_BLOB)
            }
            val key = existingKey(keyAlias)
            if (key == null) {
                // The blob outlived its key: same unrecoverable state as an
                // invalidated key, so clean up and report absence.
                purge(stored, keyAlias)
                return frame(NOT_FOUND)
            }
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, blob, 1, IV_SIZE))
            cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
            frame(OK, 0, cipher.doFinal(blob, 1 + IV_SIZE, blob.size - 1 - IV_SIZE))
        } catch (e: KeyPermanentlyInvalidatedException) {
            purge(stored, keyAlias)
            frame(NOT_FOUND)
        } catch (e: AEADBadTagException) {
            purge(stored, keyAlias)
            frame(NOT_FOUND)
        } catch (e: UnrecoverableKeyException) {
            purge(stored, keyAlias)
            frame(NOT_FOUND)
        } catch (e: KeyStoreException) {
            frame(UNAVAILABLE, E_KEYSTORE)
        } catch (e: GeneralSecurityException) {
            // A gated key the user has not authenticated with recently is
            // neither missing nor lost, so keep the blob and say so.
            if (needsAuthentication(e)) {
                frame(AUTH_REQUIRED)
            } else {
                frame(FAILURE, E_SECURITY)
            }
        } catch (e: IOException) {
            frame(FAILURE, E_IO)
        }
    }

    @JvmStatic
    fun delete(context: Context, fileName: String, keyAlias: String): ByteArray = try {
        purge(file(context, fileName), keyAlias)
        frame(OK)
    } catch (e: KeyStoreException) {
        frame(UNAVAILABLE, E_KEYSTORE)
    } catch (e: IOException) {
        frame(FAILURE, E_IO)
    }

    /// Presence only consults the file, so it never blocks on the KeyStore.
    @JvmStatic
    fun contains(context: Context, fileName: String): ByteArray =
        frame(if (file(context, fileName).exists()) OK else NOT_FOUND)
}
