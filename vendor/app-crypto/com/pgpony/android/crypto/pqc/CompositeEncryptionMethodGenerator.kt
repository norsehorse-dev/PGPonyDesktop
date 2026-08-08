// CompositeEncryptionMethodGenerator.kt
// PGPony Android — 4.0.0 Phase 2b (slice 4, encrypt side)
//
// A BouncyCastle PGPKeyEncryptionMethodGenerator for the IETF composite
// (algorithm 35, ML-KEM-768 + X25519). BC's PGPEncryptedDataGenerator
// generates ONE session key for the whole message, then asks each method
// generator to wrap it for its recipient and return the resulting PKESK
// packet. BC can't do algo 35, so we plug in here:
//
//   generate(builder, sessionKey):
//     • composite-encapsulate to the recipient's algo-35 subkey
//       (X25519 ephemeral + ML-KEM ciphertext → KEK)
//     • RFC-3394 AES-256 wrap the session key under the KEK
//     • emit a v6 algo-35 PKESK carrying ephemeral || ct || len || wrapped
//
// The returned packet is a real BouncyCastle PublicKeyEncSessionPacket
// (via its public createV6PKESKPacket factory), so the packet header and
// new-format length are produced by BC — only the algorithm-specific body
// is ours. BC then builds the SEIPDv2 (AEAD) body with the same session
// key; a composite recipient is always v6, so the pairing is correct.
//
// For v6 the session key is wrapped BARE (no symmetric-algorithm octet —
// that field is v3-PKESK-only; the algorithm lives in the SEIPDv2 packet).

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.ContainedPacket
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator
import java.security.SecureRandom

class CompositeEncryptionMethodGenerator(
    private val recipientSubkey: PGPPublicKey,
    private val random: SecureRandom = SecureRandom()
) : PGPKeyEncryptionMethodGenerator {

    override fun generate(
        dataEncryptorBuilder: PGPDataEncryptorBuilder,
        sessionKey: ByteArray
    ): ContainedPacket {
        val suite = CompositeSuite.ietfFor(recipientSubkey.algorithm)
            ?: throw PGPException("recipient subkey is not an IETF ML-KEM composite (algo 35/36)")
        val (xPub, mPub) = CompositeKeyMaterial.publicMaterial(recipientSubkey)
            ?: throw PGPException("composite subkey material is malformed")

        val enc = CompositeKem.encapsulate(xPub, mPub, random, suite)
        val wrapped = CompositeKem.wrapSessionKey(enc.kek, sessionKey)

        // Algorithm-specific fields for a v6 algo-35 PKESK:
        //   X25519 ephemeral (32) || ML-KEM ct (1088) || len (1) || wrapped
        val algoFields = CompositePkesk.encodeAlgoFields(
            enc.ephemeralX25519, enc.mlkemCiphertext, wrapped, suite
        )

        // v6 fingerprint of the encryption subkey (32 bytes). BC writes the
        // keyInfo count / key-version / fingerprint framing around it.
        return PublicKeyEncSessionPacket.createV6PKESKPacket(
            PublicKeyPacket.VERSION_6,
            recipientSubkey.fingerprint,
            suite.ietfAlgId,
            arrayOf(algoFields)
        )
    }
}
