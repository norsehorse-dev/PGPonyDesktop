// CompositeSuite.kt
// PGPony Android — 4.2.0 §1.1 (ML-KEM-1024 + X448 composite)
//
// The shared parameter model for the post-quantum composite KEMs. Both the
// IETF core (CompositeKem, algo 35/36) and the LibrePGP core
// (CompositeKemLibrePGP, algo 8) read their curve, ML-KEM level, byte
// lengths and algorithm id from a suite rather than from hardcoded 768/
// X25519 constants, so the security-critical combiner exists in ONE place
// per scheme and the 1024 parameter set is a data entry, not a second copy.
//
// The 768 suites reproduce the exact constants the 4.0.0 code shipped and
// that CompositeKemTest / CompositeDecryptTest / CompositePkeskTest already
// regression-lock. The 1024 suites add ML-KEM-1024 + X448:
//
//   IETF (draft-ietf-openpgp-pqc):
//     algo 35  ML-KEM-768  + X25519   (v6 subkey)   [shipped 4.0.0]
//     algo 36  ML-KEM-1024 + X448     (v6 subkey)   [new, §1.1]
//   LibrePGP (draft-koch-librepgp, GnuPG 2.5.x):
//     algo 8   Kyber-768   + X25519   (v5 subkey)   [shipped 4.0.0]
//     algo 8   Kyber-1024  + X448     (v5 subkey)   [new, §1.1]
//
// Note the LibrePGP asymmetry: algo 8 is a SINGLE code point for both
// levels, so a v5 algo-8 key is 768-vs-1024 only by its curve OID
// (X25519 1.3.101.110 vs X448 1.3.101.111) and Kyber length. The IETF side
// has distinct code points 35 and 36 and needs no such disambiguation.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters

/**
 * The ECDH half of a composite: native-curve X25519 or X448. [oidTail] is
 * the DER object-identifier body (no length prefix) as it appears in a v5
 * LibrePGP key packet: 1.3.101.110 for X25519, 1.3.101.111 for X448.
 */
enum class EccCurve(val keyLen: Int, val oidTail: ByteArray) {
    X25519(32, byteArrayOf(0x2b, 0x65, 0x6e)),
    X448(56, byteArrayOf(0x2b, 0x65, 0x6f));

    /**
     * Adjust a raw ECC point value to exactly [keyLen] octets. A LibrePGP
     * composite stores the point as a variable-length MPI, but the KEM needs
     * the fixed curve length: trim the low [keyLen] if longer (drops a 0x40
     * native-point prefix or high zero octets), left-pad if shorter (restores
     * a minimal MPI, as gpg emits, back to the curve length). Feeding the raw
     * MPI bytes instead makes the KDF disagree with gpg and the session-key
     * unwrap fail with "checksum failed".
     */
    fun normalizePoint(b: ByteArray): ByteArray = when {
        b.size == keyLen -> b
        b.size > keyLen -> b.copyOfRange(b.size - keyLen, b.size)
        else -> ByteArray(keyLen - b.size) + b
    }

    companion object {
        /** Match a v5 key packet's OID body (length-prefixed bytes) to a curve. */
        fun fromOidTail(bytes: ByteArray): EccCurve? =
            entries.firstOrNull { it.oidTail.contentEquals(bytes) }
    }
}

/**
 * The ML-KEM half. [seedLen] is the FIPS-203 d||z seed and is 64 octets for
 * every parameter set, which is why composite secret material barely changes
 * between 768 and 1024 (only the ECC half grows, 32 -> 56).
 */
enum class MlkemLevel(
    val params: MLKEMParameters,
    val pubLen: Int,
    val ctLen: Int,
    val seedLen: Int = 64
) {
    MLKEM768(MLKEMParameters.ml_kem_768, 1184, 1088),
    MLKEM1024(MLKEMParameters.ml_kem_1024, 1568, 1568);
}

/**
 * A composite parameter set: which OpenPGP scheme, its algorithm id, and the
 * curve + ML-KEM level it pairs. The IETF draft registers exactly two KEM
 * code points (35, 36) and GnuPG pairs the same way (ky768_cv25519,
 * ky1024_cv448), so these four suites are the whole space: there is no
 * ML-KEM-1024 + X25519.
 */
enum class CompositeSuite(
    val ietfAlgId: Int,
    val curve: EccCurve,
    val mlkem: MlkemLevel
) {
    IETF_768(35, EccCurve.X25519, MlkemLevel.MLKEM768),
    IETF_1024(36, EccCurve.X448, MlkemLevel.MLKEM1024),
    LIBREPGP_768(8, EccCurve.X25519, MlkemLevel.MLKEM768),
    LIBREPGP_1024(8, EccCurve.X448, MlkemLevel.MLKEM1024);

    /** Composite public-key material length: ECC point || ML-KEM public. */
    val compositePubLen: Int get() = curve.keyLen + mlkem.pubLen

    /** Raw composite secret material length: ECC secret || ML-KEM seed. */
    val secretLen: Int get() = curve.keyLen + mlkem.seedLen

    val isLibrePgp: Boolean get() = this == LIBREPGP_768 || this == LIBREPGP_1024

    companion object {
        /** The IETF (v6) suite for algorithm id 35 or 36, if either. */
        fun ietfFor(algId: Int): CompositeSuite? = when (algId) {
            IETF_768.ietfAlgId -> IETF_768
            IETF_1024.ietfAlgId -> IETF_1024
            else -> null
        }

        /** The LibrePGP (v5) suite for a given curve. */
        fun librePgpFor(curve: EccCurve): CompositeSuite =
            if (curve == EccCurve.X448) LIBREPGP_1024 else LIBREPGP_768
    }
}
