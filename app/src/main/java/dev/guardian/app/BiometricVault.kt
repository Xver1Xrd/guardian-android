package dev.guardian.app

import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Stores only an Android Keystore-encrypted copy of the master password. */
internal class BiometricVault(private val context: Context) {
    private val preferences = context.getSharedPreferences("guardian-biometric", Context.MODE_PRIVATE)

    val isEnabled: Boolean get() = preferences.contains(CIPHERTEXT) && preferences.contains(IV)

    fun canAuthenticate(): Boolean = context.getSystemService(BiometricManager::class.java)
        ?.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS

    fun enable(activity: MainActivity, password: CharArray, onError: (String) -> Unit) {
        if (!canAuthenticate()) {
            onError("Отпечаток пальца недоступен на этом устройстве")
            return
        }
        val copy = password.concatToString().toByteArray(StandardCharsets.UTF_8)
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
            prompt(activity, cipher, "Включить вход по отпечатку", "Подтвердите отпечаток пальца", onCancelled = {
                copy.fill(0)
            }) { authenticated ->
                try {
                    val encrypted = authenticated.doFinal(copy)
                    preferences.edit()
                        .putString(CIPHERTEXT, Base64.encodeToString(encrypted, Base64.NO_WRAP))
                        .putString(IV, Base64.encodeToString(authenticated.iv, Base64.NO_WRAP))
                        .apply()
                } catch (_: Exception) {
                    onError("Не удалось включить вход по отпечатку")
                } finally {
                    copy.fill(0)
                }
            }
        } catch (_: Exception) {
            copy.fill(0)
            onError("Не удалось подготовить вход по отпечатку")
        }
    }

    fun unlock(activity: MainActivity, onPassword: (CharArray) -> Unit, onError: (String) -> Unit) {
        val encrypted = decode(CIPHERTEXT) ?: return onError("Вход по отпечатку не настроен")
        val iv = decode(IV) ?: return onError("Вход по отпечатку не настроен")
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv)) }
            prompt(activity, cipher, "Открыть Guardian", "Подтвердите отпечаток пальца", onCancelled = {
                encrypted.fill(0)
                iv.fill(0)
            }) { authenticated ->
                try {
                    val clear = authenticated.doFinal(encrypted)
                    try {
                        onPassword(String(clear, StandardCharsets.UTF_8).toCharArray())
                    } finally {
                        clear.fill(0)
                    }
                } catch (_: Exception) {
                    onError("Не удалось открыть хранилище по отпечатку")
                } finally {
                    encrypted.fill(0)
                    iv.fill(0)
                }
            }
        } catch (_: Exception) {
            encrypted.fill(0)
            iv.fill(0)
            onError("Вход по отпечатку недоступен")
        }
    }

    private fun prompt(
        activity: MainActivity,
        cipher: Cipher,
        title: String,
        subtitle: String,
        onCancelled: () -> Unit,
        success: (Cipher) -> Unit,
    ) {
        val executor = activity.mainExecutor
        BiometricPrompt.Builder(activity)
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButton("Отмена", executor) { _, _ -> }
            .build()
            .authenticate(BiometricPrompt.CryptoObject(cipher), CancellationSignal(), executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    result.cryptoObject?.cipher?.let(success)
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onCancelled()
            })
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(STORE).apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE).apply {
            init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(-1)
                .build())
        }.generateKey()
    }

    private fun decode(name: String): ByteArray? = preferences.getString(name, null)?.let { Base64.decode(it, Base64.NO_WRAP) }

    private companion object {
        const val STORE = "AndroidKeyStore"
        const val ALIAS = "guardian.biometric.master-password.v1"
        const val CIPHERTEXT = "ciphertext"
        const val IV = "iv"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
