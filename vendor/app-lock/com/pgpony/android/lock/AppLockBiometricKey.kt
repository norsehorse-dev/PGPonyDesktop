// AppLockBiometricKey.kt
// PGPony Android 4.7.0 (item 32): ties fingerprint unlock of the PGPony PIN lock
// to the fingerprints enrolled when it was turned on.
//
// A plain BiometricPrompt result only says "a finger on this phone matched". Who
// knows the device PIN can enroll a new finger and walk past the PGPony PIN and
// its duress PIN. So fingerprint unlock goes through a CryptoObject: a Cipher on
// an Android Keystore key that needs a class 3 biometric for every use and is
// invalidated when a fingerprint is added or all are removed. The prompt
// counts only when that cipher then works. A key that is missing or
// invalidated turns fingerprint unlock off (PinLockScreen says why, once).
// The app reset and leaving PIN mode delete it.

package com.pgpony.android.lock

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object AppLockBiometricKey {

    private const val TAG = "AppLockBiometricKey"
    const val ALIAS = "pgpony_applock_biometric"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORM = "AES/GCM/NoPadding"

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /** A fresh key, replacing any old one. False when the device cannot make one. */
    fun create(): Boolean = try {
        delete()
        val builder = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Every use, class 3 biometric only (never the device credential).
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        // Below API 30 the default (no validity duration) already means every
        // use needs a biometric, and a credential cannot authorize such a key.
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(builder.build())
        generator.generateKey()
        true
    } catch (e: Exception) {
        Log.w(TAG, "Could not create the fingerprint key: ${e.message}")
        delete()
        false
    }

    fun delete() {
        try {
            val ks = keyStore()
            if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
        } catch (e: Exception) {
            Log.w(TAG, "Could not delete the fingerprint key: ${e.message}")
        }
    }

    /**
     * A cipher for the prompt's CryptoObject, or null when the key is missing or
     * invalidated (a fingerprint was added, or all were removed).
     */
    fun cipherForUnlock(): Cipher? = try {
        val key = keyStore().getKey(ALIAS, null) as? SecretKey
        if (key == null) {
            null
        } else {
            Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key) }
        }
    } catch (e: Exception) {
        // KeyPermanentlyInvalidatedException among others.
        null
    }

    /** True when [cipher], handed back by a successful prompt, really was unlocked. */
    fun proves(cipher: Cipher?): Boolean = try {
        cipher != null && cipher.doFinal(ByteArray(16)).isNotEmpty()
    } catch (_: Exception) {
        false
    }
}
