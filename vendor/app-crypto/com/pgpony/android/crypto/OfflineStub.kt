// OfflineStub.kt
// PGPony Android 4.7.0 (item 22): a secret key packet that carries no secret
// material on this device.
//
// GnuPG writes one for an offline primary (`gpg --export-secret-subkeys`, GNU
// S2K mode 1001) and for a key whose secret lives on a smartcard
// (divert-to-card, mode 1002, followed by the card serial). Bouncy Castle
// parses both. Only the 1001 form reads as isPrivateKeyEmpty: the 1002 serial
// lands where the secret material would be, so the S2K is checked first.
//
// Every place that picks or unlocks a secret key asks isStub first. Signing
// skips stubs, decryption never counts one as a locked candidate, and the
// edits that need the primary (User IDs, subkeys, expiry, revocation) refuse
// with OfflinePrimaryException instead of asking for a passphrase that can
// never work. Export and backup keep the stub as it is, so the key goes back
// into gpg as `sec#`.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.S2K
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing

object OfflineStub {

    const val SIGN_MESSAGE =
        "The primary key's secret is not on this device (offline primary). Sign with a signing subkey."

    const val EDIT_MESSAGE =
        "The primary key's secret is not on this device (offline primary). Make this change where the " +
            "primary key is kept, then import the key here again."

    /** Where a stub primary's secret lives. */
    enum class Kind { OFFLINE, CARD }

    /** True when [key] has no secret material here (GNU 1001 or 1002, or
     *  empty). GNU mode 3 carries real material and is not a stub. */
    fun isStub(key: PGPSecretKey): Boolean {
        val s2k = key.s2K
        if (s2k != null && s2k.type == S2K.GNU_DUMMY_S2K) {
            val mode = s2k.protectionMode
            if (mode == S2K.GNU_PROTECTION_MODE_NO_PRIVATE_KEY || mode == S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD) return true
        }
        return key.isPrivateKeyEmpty
    }

    /** True for a GnuPG divert-to-card stub (mode 1002). */
    fun isCardStub(key: PGPSecretKey): Boolean {
        val s2k = key.s2K ?: return false
        return s2k.type == S2K.GNU_DUMMY_S2K && s2k.protectionMode == S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD
    }

    /** The kind of stub [ring]'s primary is, or null when its secret is here. */
    fun primaryKind(ring: PGPSecretKeyRing): Kind? {
        val primary = ring.secretKey ?: return null
        if (!isStub(primary)) return null
        return if (isCardStub(primary)) Kind.CARD else Kind.OFFLINE
    }

    /** True when no secret key in [ring] carries material. */
    fun allStubs(ring: PGPSecretKeyRing): Boolean = ring.secretKeys.asSequence().all { isStub(it) }

    /** Throws [OfflinePrimaryException] when [key] is a stub. */
    fun requireSecret(key: PGPSecretKey) {
        if (isStub(key)) throw OfflinePrimaryException()
    }
}

/** An edit needs the primary key's secret, and only its stub is on this device. */
class OfflinePrimaryException : Exception(OfflineStub.EDIT_MESSAGE)
