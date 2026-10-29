// SopLibrePgpV5.kt
// PGPony Desktop 3.0.3: pgpony-sop with LibrePGP v5 keys (GnuPG and Kleopatra's Ed448 keys).
//
// A v5 signature over a document hashes a block between its hashed subpackets and the 0x05 0xFF
// trailer, and the block depends on how the signature is carried (LibrePgpV5Sig, from PGPony
// Android 4.7.3): six zero octets when detached, 't' and five zeros in a cleartext message, and the
// literal data packet's format, file name and date in an inline message. The engine handles that
// wherever it signs or verifies a whole message. SOP also works one signature packet at a time:
// it builds cleartext and inline messages out of single signatures when several keys sign, and it
// checks every signature packet of a message again on its own for the VERIFICATIONS lines. Those
// places need to know the block, and this file supplies it. v4 and v6 signatures never come here.

package com.pgpony.desktop

import com.pgpony.android.crypto.DecryptResult
import com.pgpony.android.crypto.LibrePgpV5Sig
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.PonySigGen
import com.pgpony.android.crypto.SecretKeyUnlock
import com.pgpony.android.crypto.SignerEvaluator
import com.pgpony.android.crypto.SignerStatus
import com.pgpony.android.crypto.SigningError
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.enforceArgon2Policy
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.sig.IssuerFingerprint
import org.bouncycastle.bcpg.sig.IssuerKeyID
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import java.io.ByteArrayOutputStream
import java.util.Date

/** Where a signature SOP makes will sit, which decides a v5 signature's document block. */
internal sealed class SopV5Block {
    /** A detached signature. */
    object Detached : SopV5Block()

    /** One of the signatures of a cleartext message (SopCleartext.write). */
    object Cleartext : SopV5Block()

    /** One of the signatures of an inline message built by SopInline, binary ('b') or text ('u'). */
    class Inline(val text: Boolean) : SopV5Block()
}

/** How a v5 signature packet taken out of a message is checked again on its own. */
internal sealed class SopV5Check {
    /** It is a detached signature: VerifyService already hashes the detached block. */
    object Detached : SopV5Check()

    /** The block is known: [extra] is hashed in its place. */
    class Block(val extra: ByteArray) : SopV5Check()

    /**
     * An encrypted message, whose literal data fields are not visible here. The engine checked
     * the signature while it decrypted, with those fields; its graded result stands in.
     */
    class Engine(val result: DecryptResult) : SopV5Check()
}

internal object SopLibrePgpV5 {

    /** True when [ring]'s signing key, as SigningService picks it, is a v5 key. */
    fun signsV5(ring: PGPSecretKeyRing): Boolean =
        PGPCryptoService.shared.pickSigningSecretKey(ring)?.publicKey?.version == 5

    /**
     * A v5 document signature (a binary packet) by [ring]'s signing key over [data], with the
     * document block [block] asks for. Built the way SigningService builds its signatures (same
     * key pick, unlock, hash and hashed subpackets, same errors), through PonySigGen.
     */
    fun sign(ring: PGPSecretKeyRing, passphrase: String?, data: ByteArray, text: Boolean, block: SopV5Block): ByteArray {
        val signingKey = PGPCryptoService.shared.pickSigningSecretKey(ring) ?: throw SigningError.NoSigningKey()
        enforceArgon2Policy(signingKey.s2K)
        val privateKey = try {
            signingKey.extractPrivateKey(SecretKeyUnlock.decryptor(passphrase))
        } catch (e: PGPException) {
            if (signingKey.s2KUsage.toInt() != 0) {
                if (passphrase.isNullOrEmpty()) throw SigningError.PassphraseRequired()
                throw SigningError.InvalidPassphrase()
            }
            throw SigningError.SigningFailed(e.message ?: "Failed to unlock signing key")
        }
        val type = if (text) PGPSignature.CANONICAL_TEXT_DOCUMENT else PGPSignature.BINARY_DOCUMENT
        val gen = PonySigGen(
            BcPGPContentSignerBuilder(signingKey.publicKey.algorithm, SigningService.DEFAULT_HASH_ALGORITHM),
            signingKey.publicKey
        )
        gen.init(type, privateKey)
        gen.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setIssuerFingerprint(false, signingKey.publicKey)
        }.generate())
        when (block) {
            SopV5Block.Detached -> Unit
            SopV5Block.Cleartext -> gen.setCleartext()
            // SopInline.literal: format 'b' or 'u', no file name, date 0.
            is SopV5Block.Inline -> gen.setLiteralData(if (block.text) PGPLiteralData.UTF8 else PGPLiteralData.BINARY, "", Date(0))
        }
        gen.update(data, 0, data.size)
        return try {
            ByteArrayOutputStream().also { o -> BCPGOutputStream(o).use { gen.generate().encode(it) } }.toByteArray()
        } catch (e: PGPException) {
            throw SigningError.SigningFailed(e.message ?: "PGP error")
        }
    }

    /** The literal data block an inline v5 signature in [message] (armored or binary, not encrypted) hashes. */
    fun literalBlock(message: ByteArray): ByteArray? = runCatching {
        var factory = BcPGPObjectFactory(SopArmor.binary(message))
        var literal: PGPLiteralData? = null
        while (true) {
            when (val obj = factory.nextObject() ?: break) {
                is PGPCompressedData -> factory = BcPGPObjectFactory(obj.dataStream)
                is PGPLiteralData -> {
                    if (literal != null) return@runCatching null
                    literal = obj
                    obj.inputStream.readBytes()
                }
            }
        }
        literal?.let { LibrePgpV5Sig.literalExtra(it.format, it.rawFileName, it.modificationTime) }
    }.getOrNull()

    /**
     * The (signing key, primary) fingerprints for a v5 document signature [packet] over [data]
     * that verifies with [check]'s block and grades VERIFIED against [rings]; null otherwise.
     * [all] is every signature packet of the message.
     */
    fun verify(
        rings: List<PGPPublicKeyRing>,
        packet: ByteArray,
        data: ByteArray,
        check: SopV5Check,
        all: List<ByteArray>
    ): Pair<String, String>? {
        val sig = parse(packet) ?: return null
        if (!LibrePgpV5Sig.isV5Document(sig)) return null
        return when (check) {
            SopV5Check.Detached -> null
            is SopV5Check.Block -> verifyBlock(rings, sig, data, check.extra)
            is SopV5Check.Engine -> fromEngine(rings, sig, check.result, all)
        }
    }

    private fun verifyBlock(rings: List<PGPPublicKeyRing>, sig: PGPSignature, data: ByteArray, extra: ByteArray): Pair<String, String>? {
        for (key in candidates(sig, rings)) {
            val good = runCatching { LibrePgpV5Sig.verify(sig, key, data, extra) }.getOrDefault(false)
            if (!good) continue
            // The key that verified is the signer; grade it as VerifyService does.
            if (SignerEvaluator.evaluate(sig, key, rings) != SignerStatus.VERIFIED) return null
            val ring = SignerEvaluator.signerRing(key, rings) ?: return null
            return hex(key.fingerprint) to hex(ring.publicKey.fingerprint)
        }
        return null
    }

    /**
     * The engine grades one signature of a decrypted message. It stands for [sig] only when [sig]
     * is the message's only v5 document signature and was made by the v5 key the engine names.
     */
    private fun fromEngine(rings: List<PGPPublicKeyRing>, sig: PGPSignature, result: DecryptResult, all: List<ByteArray>): Pair<String, String>? {
        if (result.signerStatus != SignerStatus.VERIFIED) return null
        val signing = result.signingKeyFingerprint ?: return null
        val primary = result.signerPrimaryFingerprint ?: return null
        if (all.count { p -> parse(p)?.let { LibrePgpV5Sig.isV5Document(it) } == true } != 1) return null
        val key = rings.asSequence().flatMap { it.publicKeys.asSequence() }
            .firstOrNull { hex(it.fingerprint).equals(signing, ignoreCase = true) } ?: return null
        if (key.version != 5) return null
        if (candidates(sig, rings, named = true).none { it.fingerprint.contentEquals(key.fingerprint) }) return null
        return signing.uppercase() to primary.uppercase()
    }

    /**
     * Keys to try for [sig]: those its issuer subpackets name first, then (unless [named]) the
     * other keys of its algorithm, as VerifyService tries them. A v5 key ID is the leftmost eight
     * octets of the fingerprint.
     */
    private fun candidates(sig: PGPSignature, rings: List<PGPPublicKeyRing>, named: Boolean = false): List<PGPPublicKey> {
        val ids = LinkedHashSet<Long>().apply { add(sig.keyID) }
        val fps = ArrayList<ByteArray>()
        for (v in listOfNotNull(sig.hashedSubPackets, sig.unhashedSubPackets)) {
            for (p in v.toArray()) {
                when (p) {
                    is IssuerKeyID -> ids.add(p.keyID)
                    is IssuerFingerprint -> fps.add(p.fingerprint)
                }
            }
        }
        val all = rings.flatMap { it.publicKeys.asSequence().toList() }.distinctBy { hex(it.fingerprint) }
        val hits = all.filter { k -> k.keyID in ids || fps.any { it.contentEquals(k.fingerprint) } }
        if (named) return hits
        return hits + all.filter { k -> k !in hits && k.algorithm == sig.keyAlgorithm }.take(MAX_TRIAL_KEYS)
    }

    private const val MAX_TRIAL_KEYS = 64 // VerifyService's bound

    private fun parse(packet: ByteArray): PGPSignature? =
        runCatching { (BcPGPObjectFactory(packet).nextObject() as? PGPSignatureList)?.get(0) }.getOrNull()

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02X".format(it) }
}
