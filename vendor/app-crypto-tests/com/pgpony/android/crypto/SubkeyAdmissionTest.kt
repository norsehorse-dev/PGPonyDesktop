// SubkeyAdmissionTest.kt
// PGPony Android 4.7.0 (item 40, #82): a re-import of your own key pair adds
// the subkeys the primary binds and the stored key lacks, the import preview
// names the subkeys it leaves out, and Key Details says where each subkey's
// secret is and why it is not usable.
//
// KeyRepository needs Room and the Android keystore, so these tests drive the
// pure decisions it calls (SubkeyAdmission.newBoundSubkeys, withSubkeys,
// graftSecrets, leftOut, issueOf, secretLocations, locationFor) the way the
// duplicate import path does: stored certificate sanitized, incoming public
// part taken from the incoming secret ring.
//
// Fixtures in /subkeyadd were made with GnuPG 2.2.27 in a fresh GNUPGHOME,
// no passphrase (--batch --pinentry-mode loopback --passphrase ""), each step
// at a --faked-system-time:
//   Key A, 7C996E61DB802C0C: quick-gen-key ed25519 cert,sign (2020-01-01),
//   quick-add-key cv25519 encr (2020-01-01, 20908878113A250F).
//     base-secret / base-public    exported after those two steps
//     plus-one-secret              after quick-add-key ed25519 sign (2025-01-02, 285C5C3FBEAE905A)
//     plus-two-secret / -public    after quick-add-key cv25519 encr (2025-07-01, 42209617489B9DBB)
//     stub-sub-secret              plus-two with the 285C... key file removed from
//                                  private-keys-v1.d, so gpg exports it as a GNU 1001 stub
//   Key B, DF8EFF7D64B71DA7: quick-gen-key rsa2048 cert,sign (2020-01-01),
//   quick-add-key rsa2048 encr (2020-01-01).
//     weak-base-secret             exported after those two steps
//     weak-plus-secret / -public   after quick-add-key rsa2048 sign at 2024-03-01 with
//                                  --allow-weak-key-signatures --cert-digest-algo SHA1
//                                  --digest-algo SHA1 (binding and back-signature SHA-1,
//                                  A453C70D...0A2866789A172A5A), then rsa2048 sign at
//                                  2025-01-02 with SHA-256 (3DEC9676...8BA7A8CC27192C96)
// The status cases for expired and revoked subkeys reuse /signsub (item 39).

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

class SubkeyAdmissionTest {

    private val calc = JcaKeyFingerprintCalculator()
    private val now = System.currentTimeMillis()

    private val aSign2025 = "285C5C3FBEAE905A"
    private val aEnc2025 = "42209617489B9DBB"
    private val bWeakFp = "A453C70D435A35BAB83246FC0A2866789A172A5A"
    private val bStrongFp = "3DEC9676F7EE189F94CC28368BA7A8CC27192C96"

    private fun bytes(path: String): ByteArray = javaClass.getResourceAsStream(path)!!.use { it.readBytes() }
    private fun secret(name: String) = PGPSecretKeyRing(bytes("/subkeyadd/$name"), calc)
    private fun publicOf(ring: PGPSecretKeyRing): ByteArray = PGPPublicKeyRing(ring.publicKeys.asSequence().toList()).encoded

    /** The certificate as the app stores it for a key pair: sanitized. */
    private fun storedPublic(ring: PGPSecretKeyRing): ByteArray = CertificateBindings.sanitized(publicOf(ring))

    private fun keyId(hex: String): Long = java.lang.Long.parseUnsignedLong(hex.takeLast(16), 16)

    private fun fpOf(ring: PGPSecretKeyRing, keyIdHex: String): String =
        org.bouncycastle.util.encoders.Hex.toHexString(ring.getSecretKey(keyId(keyIdHex))!!.publicKey.fingerprint).uppercase()

    /** The re-import of [incomingName] onto the stored key pair [storedName]. */
    private class Reimport(val certificate: ByteArray, val ring: PGPSecretKeyRing, val added: Set<String>, val grafted: Int)

    private fun reimport(storedName: String, incomingName: String): Reimport {
        val storedSecret = secret(storedName)
        val stored = storedPublic(storedSecret)
        val incomingSecret = secret(incomingName)
        val incoming = publicOf(incomingSecret)
        val add: Set<String> = SubkeyAdmission.newBoundSubkeys(stored, incoming, incomingHasSecret = true)
            .map { it.fingerprintHex.uppercase() }.toSet()
        val certificate = SubkeyAdmission.withSubkeys(stored, incoming, add)
        val grafted: Pair<PGPSecretKeyRing, Int> =
            SubkeyAdmission.graftSecrets(storedSecret, incomingSecret, PGPPublicKeyRing(certificate, calc))
        return Reimport(certificate, grafted.first, add, grafted.second)
    }

    // ── Re-import of your own key pair ────────────────────────────────

    @Test
    fun `one new subkey is added with its public part and its secret`() {
        val r = reimport("base-secret.pgp", "plus-one-secret.pgp")
        assertEquals(1, r.added.size)
        assertEquals(2, SubkeyAdmission.subkeyFingerprints(r.certificate).size)
        val report = CertificateBindings.analyze(r.certificate)!!
        val added = report.subkeys.single { it.fingerprintHex.uppercase() in r.added }
        assertTrue(added.bound && added.backSigned)
        assertEquals(1, r.grafted)
        val sk = r.ring.getSecretKey(keyId(aSign2025))
        assertNotNull(sk)
        assertFalse(OfflineStub.isStub(sk!!))
        assertNotNull(sk.extractPrivateKey(null))
        // The added signing subkey is the one that signs now (item 39).
        assertEquals(keyId(aSign2025), PGPCryptoService.shared.pickSigningSecretKey(r.ring)?.keyID)
    }

    @Test
    fun `two new subkeys are added with their public parts and their secrets`() {
        val r = reimport("base-secret.pgp", "plus-two-secret.pgp")
        assertEquals(2, r.added.size)
        assertEquals(3, SubkeyAdmission.subkeyFingerprints(r.certificate).size)
        assertEquals(2, r.grafted)
        val keys = r.ring.secretKeys.asSequence().toList()
        assertEquals(4, keys.size)
        assertTrue(keys.none { OfflineStub.isStub(it) })
        assertNotNull(r.ring.getSecretKey(keyId(aEnc2025)))
        // The secret ring and the certificate agree on every subkey.
        assertEquals(
            SubkeyAdmission.subkeyFingerprints(r.certificate),
            SubkeyAdmission.subkeyFingerprints(r.ring.encoded)
        )
    }

    @Test
    fun `a public-only re-import adds no subkeys`() {
        val stored = storedPublic(secret("base-secret.pgp"))
        val incoming = bytes("/subkeyadd/plus-two-public.pgp")
        assertTrue(SubkeyAdmission.newBoundSubkeys(stored, incoming, incomingHasSecret = false).isEmpty())
        // The same certificate with secret material present would add both.
        assertEquals(2, SubkeyAdmission.newBoundSubkeys(stored, incoming, incomingHasSecret = true).size)
        // And the item 24 merge still adds no components to a key pair.
        val merged = CertificateMerge.mergeDetailed(stored, incoming, isKeyPair = true).bytes
        assertEquals(1, SubkeyAdmission.subkeyFingerprints(merged).size)
    }

    @Test
    fun `a subkey exported as a stub is added as a stub`() {
        val r = reimport("base-secret.pgp", "stub-sub-secret.pgp")
        assertEquals(2, r.added.size)
        assertEquals(2, r.grafted)
        assertTrue(OfflineStub.isStub(r.ring.getSecretKey(keyId(aSign2025))!!))
        assertFalse(OfflineStub.isStub(r.ring.getSecretKey(keyId(aEnc2025))!!))
        val locations = SubkeyAdmission.secretLocations(r.ring.encoded)
        assertEquals(SubkeyAdmission.SecretLocation.OFFLINE_STUB, locations[fpOf(r.ring, aSign2025)])
        assertEquals(SubkeyAdmission.SecretLocation.ON_DEVICE, locations[fpOf(r.ring, aEnc2025)])
    }

    @Test
    fun `a stub never replaces a secret already held`() {
        val r = reimport("plus-two-secret.pgp", "stub-sub-secret.pgp")
        assertTrue(r.added.isEmpty())
        assertEquals(0, r.grafted)
        assertFalse(OfflineStub.isStub(r.ring.getSecretKey(keyId(aSign2025))!!))
    }

    @Test
    fun `a held stub is replaced by real secret material`() {
        val r = reimport("stub-sub-secret.pgp", "plus-two-secret.pgp")
        assertTrue(r.added.isEmpty())
        assertEquals(1, r.grafted)
        assertFalse(OfflineStub.isStub(r.ring.getSecretKey(keyId(aSign2025))!!))
    }

    @Test
    fun `a subkey bound with SHA-1 after the cutoff is left out and reported`() {
        val r = reimport("weak-base-secret.pgp", "weak-plus-secret.pgp")
        assertEquals(setOf(bStrongFp), r.added)
        assertFalse(bWeakFp in SubkeyAdmission.subkeyFingerprints(r.certificate))
        assertEquals(1, r.grafted)
        assertEquals(keyId(bStrongFp), PGPCryptoService.shared.pickSigningSecretKey(r.ring)?.keyID)

        for (name in listOf("weak-plus-public.pgp", "weak-plus-secret.pgp")) {
            val leftOut = SubkeyAdmission.leftOut(bytes("/subkeyadd/$name"), now)
            assertEquals(name, 1, leftOut.size)
            assertEquals(bWeakFp, leftOut.single().subkey.fingerprintHex.uppercase())
            assertEquals(SubkeyAdmission.Issue.WEAK_HASH, leftOut.single().issue)
        }
        val raw = bytes("/subkeyadd/weak-plus-public.pgp")
        assertTrue(SubkeyAdmission.weakHashOnly(raw, bWeakFp, backSignature = false))
        assertFalse(SubkeyAdmission.weakHashOnly(raw, bStrongFp, backSignature = false))
        assertFalse(SubkeyAdmission.weakHashOnly(raw, bStrongFp, backSignature = true))
    }

    @Test
    fun `a binding that does not verify is reported as no valid binding`() {
        val raw = corruptBinding(bytes("/subkeyadd/weak-plus-public.pgp"), bStrongFp)
        val byFp = SubkeyAdmission.leftOut(raw, now).associate { it.subkey.fingerprintHex.uppercase() to it.issue }
        assertEquals(SubkeyAdmission.Issue.NO_VALID_BINDING, byFp[bStrongFp])
        assertEquals(SubkeyAdmission.Issue.WEAK_HASH, byFp[bWeakFp])
    }

    @Test
    fun `a key whose subkeys are all good leaves nothing out`() {
        assertTrue(SubkeyAdmission.leftOut(bytes("/subkeyadd/plus-two-secret.pgp"), now).isEmpty())
        assertTrue(SubkeyAdmission.leftOut(bytes("/subkeyadd/plus-two-public.pgp"), now).isEmpty())
    }

    /** [raw] with the last octet of the first binding signature of [fpHex] flipped. */
    private fun corruptBinding(raw: ByteArray, fpHex: String): ByteArray {
        val packets = CertificateBindings.packets(raw)
        val out = ByteArrayOutputStream()
        var flipNext = false
        for (p in packets) {
            var body = p.body
            if (p.tag == 14) {
                flipNext = CertificateBindings.KeyBody(body).fingerprintHex.equals(fpHex, ignoreCase = true)
            } else if (p.tag == 2 && flipNext) {
                body = body.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() }
                flipNext = false
            }
            out.write(CertificateBindings.frame(p.tag, body))
        }
        return out.toByteArray()
    }

    // ── Status mapping ────────────────────────────────────────────────

    private fun state(
        bound: Boolean = true,
        backSigned: Boolean = true,
        flags: Int? = 0x02,
        revoked: Boolean = false,
        expiresAt: Long? = null,
        algorithm: Int = 22
    ) = CertificateBindings.SubkeyState(
        fingerprintHex = "AB".repeat(20),
        keyId = 1L,
        algorithm = algorithm,
        bound = bound,
        backSigned = backSigned,
        revoked = revoked,
        expiresAtMs = expiresAt,
        keyFlags = flags,
        bindings = if (bound) {
            listOf(CertificateBindings.SelfSig(createdMs = 1_000L, keyExpiresAtMs = expiresAt, keyFlags = flags, backSigned = backSigned))
        } else emptyList()
    )

    @Test
    fun `status mapping for each reason`() {
        val yes = { true }
        assertNull(SubkeyAdmission.issueOf(state(), now))
        assertEquals(SubkeyAdmission.Issue.NO_VALID_BINDING, SubkeyAdmission.issueOf(state(bound = false), now))
        assertEquals(SubkeyAdmission.Issue.WEAK_HASH, SubkeyAdmission.issueOf(state(bound = false), now, weakBinding = yes))
        assertEquals(SubkeyAdmission.Issue.NO_BACK_SIGNATURE, SubkeyAdmission.issueOf(state(backSigned = false), now))
        assertEquals(
            SubkeyAdmission.Issue.WEAK_HASH,
            SubkeyAdmission.issueOf(state(backSigned = false), now, weakBackSignature = yes)
        )
        // An encryption subkey needs no back-signature.
        assertNull(SubkeyAdmission.issueOf(state(backSigned = false, flags = 0x0C, algorithm = 18), now))
        // Without key flags, a sign-only algorithm counts as signing.
        assertEquals(
            SubkeyAdmission.Issue.NO_BACK_SIGNATURE,
            SubkeyAdmission.issueOf(state(backSigned = false, flags = null, algorithm = 22), now)
        )
        assertEquals(SubkeyAdmission.Issue.REVOKED, SubkeyAdmission.issueOf(state(revoked = true), now))
        assertEquals(SubkeyAdmission.Issue.EXPIRED, SubkeyAdmission.issueOf(state(expiresAt = now - 1), now))
        assertNull(SubkeyAdmission.issueOf(state(expiresAt = now + 60_000), now))
        // A reason that drops the subkey comes before revoked or expired.
        assertEquals(
            SubkeyAdmission.Issue.NO_VALID_BINDING,
            SubkeyAdmission.issueOf(state(bound = false, revoked = true, expiresAt = now - 1), now)
        )
        assertTrue(SubkeyAdmission.isAdmissible(state(revoked = true)))
        assertFalse(SubkeyAdmission.isAdmissible(state(backSigned = false)))
        assertFalse(SubkeyAdmission.isAdmissible(state(bound = false)))
    }

    private fun signsubRaw(name: String): ByteArray =
        publicOf(PGPSecretKeyRing(bytes("/signsub/$name"), calc))

    private fun subkeyCreatedOn(report: CertificateBindings.Report, date: String): CertificateBindings.SubkeyState {
        val fmt = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).apply { timeZone = TimeZone.getTimeZone("UTC") }
        return report.subkeys.single { fmt.format(java.util.Date(it.createdAtMs)) == date }
    }

    @Test
    fun `status from real certificates - expired and revoked`() {
        val expired = signsubRaw("expired-first.pgp")
        val er = CertificateBindings.analyze(expired)!!
        assertEquals(
            SubkeyAdmission.Issue.EXPIRED,
            SubkeyAdmission.issueIn(expired, er, subkeyCreatedOn(er, "2020-01-02").fingerprintHex, now)
        )
        assertNull(SubkeyAdmission.issueIn(expired, er, subkeyCreatedOn(er, "2026-01-01").fingerprintHex, now))

        val revoked = signsubRaw("revoked.pgp")
        val rr = CertificateBindings.analyze(revoked)!!
        assertEquals(
            SubkeyAdmission.Issue.REVOKED,
            SubkeyAdmission.issueIn(revoked, rr, subkeyCreatedOn(rr, "2020-02-01").fingerprintHex, now)
        )
        assertNull(SubkeyAdmission.issueIn(revoked, rr, subkeyCreatedOn(rr, "2020-01-02").fingerprintHex, now))
    }

    @Test
    fun `secret location for each case`() {
        val fp = "AB".repeat(20)
        val none = emptySet<String>()
        // A public key shows no location.
        assertNull(SubkeyAdmission.locationFor(fp, isKeyPair = false, isCardBacked = false, cardFingerprints = none, held = emptyMap()))
        // Card-backed: on the card when it is one of the card's keys, or the card's keys are not recorded.
        assertEquals(
            SubkeyAdmission.SecretLocation.ON_CARD,
            SubkeyAdmission.locationFor(fp, isKeyPair = false, isCardBacked = true, cardFingerprints = none, held = emptyMap())
        )
        assertEquals(
            SubkeyAdmission.SecretLocation.ON_CARD,
            SubkeyAdmission.locationFor(fp, false, true, setOf(fp.lowercase()), emptyMap())
        )
        assertEquals(
            SubkeyAdmission.SecretLocation.NOT_PRESENT,
            SubkeyAdmission.locationFor(fp, false, true, setOf("CD".repeat(20)), emptyMap())
        )
        // A key pair reads its secret ring; a subkey missing from it is not present.
        assertEquals(
            SubkeyAdmission.SecretLocation.OFFLINE_STUB,
            SubkeyAdmission.locationFor(fp, true, false, none, mapOf(fp to SubkeyAdmission.SecretLocation.OFFLINE_STUB))
        )
        assertEquals(SubkeyAdmission.SecretLocation.NOT_PRESENT, SubkeyAdmission.locationFor(fp, true, false, none, emptyMap()))

        // From the packets: real material, a 1001 stub, a 1002 stub, a public subkey.
        val stubRing = secret("stub-sub-secret.pgp")
        val raw = stubRing.encoded
        val held = SubkeyAdmission.secretLocations(raw)
        assertEquals(3, held.size)
        assertEquals(SubkeyAdmission.SecretLocation.OFFLINE_STUB, held[fpOf(stubRing, aSign2025)])
        assertEquals(2, held.values.count { it == SubkeyAdmission.SecretLocation.ON_DEVICE })
        val card = SubkeyAdmission.secretLocations(asCardStub(raw, fpOf(stubRing, aSign2025)))
        assertEquals(SubkeyAdmission.SecretLocation.ON_CARD, card[fpOf(stubRing, aSign2025)])
        assertTrue(
            SubkeyAdmission.secretLocations(bytes("/subkeyadd/plus-two-public.pgp")).values
                .all { it == SubkeyAdmission.SecretLocation.NOT_PRESENT }
        )
    }

    /** [raw] with the GNU stub of subkey [fpHex] turned into divert-to-card
     *  (mode 1002), followed by a card serial (length octet, then the serial)
     *  as gpg writes it. */
    private fun asCardStub(raw: ByteArray, fpHex: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (p in CertificateBindings.packets(raw)) {
            var body = p.body
            if (p.tag == 7) {
                val pub = CertificateBindings.publicPart(p.tag, body)!!
                if (CertificateBindings.KeyBody(pub).fingerprintHex.equals(fpHex, ignoreCase = true)) {
                    body = body.copyOf()
                    for (i in pub.size until body.size - 3) {
                        if (body[i] == 'G'.code.toByte() && body[i + 1] == 'N'.code.toByte() && body[i + 2] == 'U'.code.toByte()) {
                            body[i + 3] = 2
                            body = body + byteArrayOf(16) + ByteArray(16) { 0x42 }
                            break
                        }
                    }
                }
            }
            out.write(CertificateBindings.frame(p.tag, body))
        }
        return out.toByteArray()
    }
}
