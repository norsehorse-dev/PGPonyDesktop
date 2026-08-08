// CompositeKeyMaterial.kt
// PGPony Android — 4.0.0 Phase 2b
//
// Locate the IETF composite (algo 35) encryption subkey in a keyring and
// extract its raw key material. BouncyCastle parses the v6 composite
// subkey into an UnknownBCPGKey (it doesn't understand algo 35 but stores
// the bytes verbatim thanks to the v6 key-material length), so we read the
// key packet's key bytes directly — no hand parsing of the packet needed.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing

object CompositeKeyMaterial {

    const val ALGORITHM_ID = CompositeKem.ALGORITHM_ID // 35

    /** The composite ML-KEM+X25519 encryption subkey in [ring], if present. */
    fun encryptionSubkey(ring: PGPPublicKeyRing): PGPPublicKey? =
        ring.publicKeys.asSequence().firstOrNull { CompositeSuite.ietfFor(it.algorithm) != null }

    /** Does [ring] carry a composite ML-KEM+X25519 encryption subkey? */
    fun isComposite(ring: PGPPublicKeyRing): Boolean = encryptionSubkey(ring) != null

    /**
     * Raw composite public key material for an algo-35 key, split into
     * (X25519 pub 32, ML-KEM-768 pub 1184). Null if [pubKey] isn't algo 35
     * or the material isn't the expected length.
     */
    /** The IETF suite (algo 35 or 36) of [pubKey], or null if not composite. */
    fun suiteOf(pubKey: PGPPublicKey): CompositeSuite? =
        CompositeSuite.ietfFor(pubKey.algorithm)

    fun publicMaterial(pubKey: PGPPublicKey): Pair<ByteArray, ByteArray>? {
        val suite = suiteOf(pubKey) ?: return null
        val bytes = pubKey.publicKeyPacket.key.encoded
        if (bytes.size != suite.compositePubLen) return null
        return CompositeKem.splitPublic(bytes, suite)
    }
}
