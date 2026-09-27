// KeyUsePolicy.kt
// PGPony Desktop 3.0.0: which keys may be used to sign or encrypt (Android 4.5.3).
//
// An expired key used to sign or encrypt with no warning; only decrypting or verifying afterward
// flagged it. Android 4.5.3 refuses to sign with, or encrypt to, an expired key unless the user
// turns on "Allow expired keys" (off by default). Desktop applies the same rule on every surface
// that signs or encrypts: the GUI, the CLI, the git shim and watch folders. The check is on the
// key's overall (primary) expiry, as on Android.

package com.pgpony.desktop

import com.pgpony.android.data.PGPKeyEntity
import java.util.prefs.Preferences

/** A selected key has expired and "Allow expired keys" is off. The message says which. */
class ExpiredKeyException(message: String) : Exception(message)

object KeyUsePolicy {

    /** Same key name as the Android setting. */
    const val KEY_ALLOW_EXPIRED = "allow_expired_keys"

    /** Test hook: a scratch node instead of the real one. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun allowExpiredKeys(): Boolean = prefs().getBoolean(KEY_ALLOW_EXPIRED, false)

    fun setAllowExpiredKeys(enabled: Boolean) {
        prefs().putBoolean(KEY_ALLOW_EXPIRED, enabled)
        runCatching { prefs().flush() }
    }

    fun isExpired(key: PGPKeyEntity, nowMs: Long = System.currentTimeMillis()): Boolean =
        key.expiresAt?.let { it <= nowMs } == true

    private fun label(key: PGPKeyEntity): String = key.userID.ifBlank { key.shortFingerprint }

    /**
     * Throws [ExpiredKeyException] when [signer] or any of [recipients] has expired and expired
     * keys are not allowed. The signer is reported first, as Android's Encrypt screen does.
     */
    fun requireUsable(recipients: Collection<PGPKeyEntity>, signer: PGPKeyEntity?) {
        if (allowExpiredKeys()) return
        if (signer != null && isExpired(signer)) {
            throw ExpiredKeyException(tr("encrypt_expired_signing_blocked"))
        }
        val expired = recipients.filter { isExpired(it) }
        if (expired.isNotEmpty()) {
            throw ExpiredKeyException(tr("encrypt_expired_recipient_blocked", expired.joinToString(", ") { label(it) }))
        }
    }
}
