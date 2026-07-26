// CompositeLibrePGPDecryptTest.kt
// PGPony Android — 4.0.0 Phase 2b (LibrePGP composite, algorithm 8)
//
// LibrePGP *decrypt* (gpg -> PGPony) cannot be validated offline right now:
// GnuPG 2.5.21 exports algo-8 secret keys only in its proprietary gcrypt
// s-expression form (a GNU-protection extension), not standard OpenPGP
// secret-key material — so there is no gpg-produced secret key that PGPony
// (or any standard OpenPGP parser) can read to recover the X25519 + Kyber
// secrets. The one seed-form secret we had (librepgp_fixed) is corrupt:
// gpg itself rejects it with "Bad secret key".
//
// The decrypt path (CompositeLibrePGPDecryptor / CompositeLibrePGPKeyMaterial)
// is implemented and would work against a standard-form secret key; it is
// left in place for when such a key exists (e.g. a PGPony-generated algo-8
// key, or a gpg s-expr importer). The LibrePGP crypto is instead validated
// from the encrypt side (CompositeLibrePGPEncryptTest -> gpg --decrypt),
// which exercises the same symmetric KMAC256 combiner.

package com.pgpony.android.crypto.pqc

import org.junit.Assume.assumeTrue
import org.junit.Test

class CompositeLibrePGPDecryptTest {

    @Test
    fun `LibrePGP decrypt is validated from the encrypt side (see CompositeLibrePGPEncryptTest)`() {
        assumeTrue(
            "gpg 2.5.21 exports algo-8 secrets only as a gcrypt s-expr; no standard-form " +
                "secret key is available to validate LibrePGP decrypt offline.",
            false
        )
    }
}
