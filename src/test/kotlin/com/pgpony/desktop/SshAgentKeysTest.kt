// SshAgentKeysTest.kt
// D15 validation — the PGP→SSH public-key conversion (SshAgentKeys.publicBlob). Runs against
// real generated key material so the BcPGPKeyConverter path and the wire layout are exercised
// together; the full identities()/sign() flow needs a keyring database and lives in the manual
// `ssh-add -L` / `ssh` matrix rows (2.0.0 §8).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import java.math.BigInteger
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SshAgentKeysTest {

    private val crypto = PGPCryptoService.shared

    private fun masterPub(algorithm: KeyAlgorithm) = crypto.importArmoredKey(
        crypto.generateKeyPair(
            name = "SSH Test", email = "ssh@pgpony.app", algorithm = algorithm, passphrase = "pw"
        ).armoredPublicKey
    ).publicKeyRing!!.publicKey

    @Test
    fun ed25519PrimaryConvertsToAnSshEd25519Blob() {
        val pub = masterPub(KeyAlgorithm.ED25519_CV25519)
        val blob = SshAgentKeys.publicBlob(pub)!!
        val r = SshWire.Reader(blob)
        assertEquals("ssh-ed25519", String(r.string()))
        val point = r.string()
        assertEquals(32, point.size, "an ed25519 point is 32 bytes")
        // The point must be the same one BC hands back — no armor prefix, no truncation.
        val expected = (BcPGPKeyConverter().getPublicKey(pub) as Ed25519PublicKeyParameters).encoded
        assertContentEquals(expected, point)
    }

    @Test
    fun rsaPrimaryConvertsToAnSshRsaBlobWithEThenN() {
        val pub = masterPub(KeyAlgorithm.RSA_2048)
        val blob = SshAgentKeys.publicBlob(pub)!!
        val r = SshWire.Reader(blob)
        assertEquals("ssh-rsa", String(r.string()))
        val e = BigInteger(1, r.string())
        val n = BigInteger(1, r.string())
        val params = BcPGPKeyConverter().getPublicKey(pub) as RSAKeyParameters
        assertEquals(params.exponent, e, "exponent e comes first on the ssh-rsa wire")
        assertEquals(params.modulus, n, "modulus n comes second")
        assertTrue(n.bitLength() in 2040..2048, "a 2048-bit modulus")
    }

    @Test
    fun anEncryptionOnlyKeyHasNoSshName() {
        // The Cv25519 encryption subkey (algorithm 18, ECDH) is not a signing key type SSH
        // knows; publicBlob must return null rather than inventing a blob.
        val ring = crypto.importArmoredKey(
            crypto.generateKeyPair(
                name = "SSH Test", email = "ssh@pgpony.app",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "pw"
            ).armoredPublicKey
        ).publicKeyRing!!
        val encSub = ring.publicKeys.asSequence().firstOrNull { !it.isMasterKey }
        assertNull(encSub?.let { SshAgentKeys.publicBlob(it) }, "ECDH encryption key is not an SSH identity")
    }

    @Test
    fun commentNamesTheKeyAndTheApp() {
        val comment = SshAgentKeys.commentFor(
            com.pgpony.android.data.PGPKeyEntity(
                id = "FP", fingerprint = "FP", userID = "Alice <alice@x>", userName = "Alice",
                userEmail = "alice@x", algorithm = KeyAlgorithm.ED25519_CV25519,
                isKeyPair = true, createdAt = 0L
            )
        )
        assertEquals("alice@x (PGPony)", comment)
    }
}
