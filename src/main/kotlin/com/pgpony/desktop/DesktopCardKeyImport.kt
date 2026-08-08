// DesktopCardKeyImport.kt
// PGPony Desktop — D21: the card I/O for moving a software key onto the card (keytocard).
//
// CardKeyImport.kt is the pure, offline-verified half (component extraction + Extended Header
// List). This drives the card: unlock the keyring key, set the slot's algorithm attributes,
// send the odd PUT DATA import APDU through the RAW transport (the vendored session's putData is
// even-instruction only), then write the key's EXISTING fingerprint and creation time to the
// slot — existing, not fresh, because it is the same key, so the card slot must match the
// keyring entry (and gpg's own fingerprint) for pairing to link.
//
// Primary RSA key → Signature slot; RSA encryption subkey → Decryption slot; RSA auth subkey →
// Authentication slot when present. On-card generation stays the more secure default (that
// secret never existed off-card); this is the deliberate trade for a backup-able card key.

package com.pgpony.desktop

import com.pgpony.android.crypto.SubkeyCapability
import com.pgpony.android.crypto.card.CardInfo
import com.pgpony.android.crypto.card.CardSlot
import com.pgpony.android.crypto.card.CardTransport
import com.pgpony.android.crypto.card.CommandApdu
import com.pgpony.android.crypto.card.OpenPgpCard
import com.pgpony.android.crypto.card.OpenPgpCardException
import com.pgpony.android.crypto.card.OpenPgpCardSession
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider

object DesktopCardKeyImport {

    // Odd PUT DATA (INS 0xDB, P1P2 0x3FFF) — the key-import instruction (OpenPGP card spec §7.2.8).
    private const val INS_PUT_DATA_ODD = 0xDB
    private const val P1_IMPORT = 0x3F
    private const val P2_IMPORT = 0xFF
    private const val RSA_GENERAL = 1
    private const val RSA_ENCRYPT = 2
    private const val RSA_SIGN = 3

    /** What was moved, for the confirmation message. */
    data class Result(val cardInfo: CardInfo, val slotsWritten: List<String>)

    /**
     * Move the RSA (sub)keys of [ring] onto the card behind [transport]. [passphrase] unlocks the
     * secret material; [adminPin] authorizes the write; [format] is the RSA import format the card
     * expects (the knob to try if a card rejects the import). Throws with a card-status message on
     * failure. The card's private keys after this are the SAME keys as the software copy, so the
     * user keeps their backup and gains a hardware copy.
     */
    fun moveToCard(
        transport: CardTransport,
        ring: PGPSecretKeyRing,
        passphrase: String?,
        adminPin: String,
        format: RsaImportFormat
    ): Result {
        val session = OpenPgpCardSession(transport)
        session.select()
        session.verify(OpenPgpCard.PW3_ADMIN, adminPin.toByteArray(Charsets.UTF_8))

        val written = ArrayList<String>()

        // Primary → Signature slot (the primary must be an RSA key to import here).
        val primary = ring.secretKey
        requireRsa(primary.publicKey) { "the primary key is not RSA" }
        importOne(session, transport, CardSlot.SIGNATURE, CardImportSlot.SIGNATURE, primary, passphrase, format)
        written += "Signature"

        // Subkeys → Decryption (encrypt-capable) and Authentication (auth-capable) slots.
        val iterator = ring.secretKeys
        while (iterator.hasNext()) {
            val sk = iterator.next()
            if (sk.publicKey.isMasterKey) continue
            if (sk.publicKey.algorithm !in intArrayOf(RSA_GENERAL, RSA_ENCRYPT, RSA_SIGN)) continue
            val caps = SubkeyCapability.fromPgpPublicKey(sk.publicKey, algorithmOf(sk.publicKey), false)
            when {
                SubkeyCapability.hasCapability(caps, SubkeyCapability.Encrypt) -> {
                    importOne(session, transport, CardSlot.DECRYPTION, CardImportSlot.DECRYPTION, sk, passphrase, format)
                    written += "Decryption"
                }
                SubkeyCapability.hasCapability(caps, SubkeyCapability.Authenticate) -> {
                    importOne(session, transport, CardSlot.AUTHENTICATION, CardImportSlot.AUTHENTICATION, sk, passphrase, format)
                    written += "Authentication"
                }
            }
        }

        return Result(session.readCardInfo(), written)
    }

    private fun importOne(
        session: OpenPgpCardSession,
        transport: CardTransport,
        cardSlot: CardSlot,
        importSlot: CardImportSlot,
        secretKey: PGPSecretKey,
        passphrase: String?,
        format: RsaImportFormat
    ) {
        val pub = secretKey.publicKey
        val priv = unlock(secretKey, passphrase)
            ?: throw OpenPgpCardException.Malformed("could not unlock the key — wrong passphrase?")
        val comps = CardKeyImport.rsaComponents(priv)

        // Set the slot's algorithm attributes to match the key being imported: modulus size and the
        // import format (which components the Extended Header List will carry). The card uses these
        // stored attributes to know how many bytes each imported component should be, so they MUST
        // be written before the import APDU and MUST agree with the Extended Header List below.
        session.setAlgorithmAttributes(cardSlot, CardKeyImport.rsaAttributes(comps.modulusBits, format))

        val ehl = CardKeyImport.buildRsaImport(importSlot, format, comps)
        val apdu = CommandApdu(
            cla = 0x00, ins = INS_PUT_DATA_ODD, p1 = P1_IMPORT, p2 = P2_IMPORT,
            data = ehl, extended = true
        ).toBytes()
        val resp = transport.transceive(apdu)
        checkStatus(resp, cardSlot, apdu)

        // The card slot carries the key's OWN fingerprint + creation time so it matches the keyring.
        session.writeFingerprint(cardSlot, pub.fingerprint)
        session.writeGenerationTime(cardSlot, pub.creationTime.time / 1000L)
    }

    /** Unlock with the empty passphrase first (PGPony's default keys), then the supplied one. */
    private fun unlock(secretKey: PGPSecretKey, passphrase: String?) =
        attemptUnlock(secretKey, "") ?: passphrase?.let { attemptUnlock(secretKey, it) }

    private fun attemptUnlock(secretKey: PGPSecretKey, pass: String) = try {
        secretKey.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(pass.toCharArray())
        )
    } catch (_: Exception) {
        null
    }

    private fun algorithmOf(pub: PGPPublicKey) = com.pgpony.android.crypto.PGPCryptoService.shared.detectAlgorithm(pub)

    private inline fun requireRsa(pub: PGPPublicKey, message: () -> String) {
        if (pub.algorithm !in intArrayOf(RSA_GENERAL, RSA_ENCRYPT, RSA_SIGN)) {
            throw OpenPgpCardException.Malformed(message())
        }
    }

    /**
     * A 9000 status word is success; anything else names the SW so a card refusal is legible.
     * On failure the import APDU's envelope bytes (CLA/INS/P1P2, the 4D length, the CRT, and the
     * start of the 7F48 template) are appended as hex — that prefix is where a parse-level refusal
     * such as 6984 lives, so it can be compared byte-for-byte against the card's expected format.
     */
    private fun checkStatus(response: ByteArray, slot: CardSlot, apdu: ByteArray) {
        if (response.size < 2) throw OpenPgpCardException.Communication("no response from the card writing $slot")
        val sw = ((response[response.size - 2].toInt() and 0xFF) shl 8) or (response[response.size - 1].toInt() and 0xFF)
        if (sw == 0x9000) return
        val hint = when (sw) {
            0x6A80, 0x6A88 -> " (the card rejected the key format — try the other import format)"
            0x6984 -> " (referenced data invalidated — the card rejected the import envelope; format may be CRT-only)"
            0x6D00 -> " (the card does not support this instruction)"
            0x6982, 0x6983 -> " (admin PIN not accepted or blocked)"
            else -> ""
        }
        val envelope = apdu.copyOfRange(0, minOf(apdu.size, 32)).joinToString(" ") { "%02X".format(it) }
        throw OpenPgpCardException.Communication(
            "card refused the import to $slot: SW=%04X".format(sw) + hint +
                " [sent ${apdu.size} bytes, envelope: $envelope]"
        )
    }
}
