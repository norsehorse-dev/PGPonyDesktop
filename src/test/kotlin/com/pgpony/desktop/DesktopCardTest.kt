// DesktopCardTest.kt
// D7 validation, offline half — everything that doesn't need a physical reader:
//   • the card pairing/linking logic (importCardKey, the A1 subkey-scan link rule,
//     importGeneratedCardKey) against synthetic CardInfo built from real generated keys;
//   • DesktopCardOps.matchCardDecryptKey routing a message to a paired card-backed row;
//   • the PW1 cache twin's enable/duration/expiry/sentinel/clear semantics on a scratch node;
//   • DesktopCardReader degrading cleanly when no PC/SC service is present.
// The APDU protocol itself is covered by the vendored card unit suite (app-crypto-tests);
// live reader behavior is the manual YubiKey 5 / Token2 matrix.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.card.CardInfo
import com.pgpony.android.crypto.card.CardPinCache
import com.pgpony.android.crypto.card.CardSlot
import com.pgpony.android.crypto.card.CardSlotInfo
import com.pgpony.android.data.PGPDatabase
import kotlinx.coroutines.runBlocking
import org.bouncycastle.util.encoders.Hex
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesktopCardTest {

    private val crypto = PGPCryptoService.shared

    private fun temp(): Triple<PGPDatabase, DesktopKeyRepository, Path> {
        val dir = Files.createTempDirectory("pgpony-card-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return Triple(db, DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys"))), dir)
    }

    private fun generate(email: String) = crypto.generateKeyPair(
        name = "Card Test", email = email,
        algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "test-passphrase"
    )

    /** Fingerprints of a generated key's primary + its (encryption) subkey, uppercased. */
    private fun ringFingerprints(armoredPublic: String): Pair<String, String> {
        val ring = crypto.importArmoredKey(armoredPublic).publicKeyRing!!
        val fps = ring.publicKeys.asSequence()
            .map { Hex.toHexString(it.fingerprint).uppercase() }.toList()
        return fps.first() to fps.last()
    }

    private fun cardInfoFor(
        sigFp: String?, decFp: String?, serial: String = "01020304"
    ) = CardInfo(
        aidHex = "D2760001240103040006${serial}0000",
        manufacturerName = "Yubico",
        serialHex = serial,
        slots = listOf(
            CardSlotInfo(CardSlot.SIGNATURE, KeyAlgorithm.ED25519_CV25519, "Ed25519", sigFp, null),
            CardSlotInfo(CardSlot.DECRYPTION, KeyAlgorithm.ED25519_CV25519, "Cv25519", decFp, null),
            CardSlotInfo(CardSlot.AUTHENTICATION, null, "—", null, null)
        ),
        pw1TriesRemaining = 3,
        pw3TriesRemaining = 3
    )

    // ── Pairing / linking ───────────────────────────────────────────────

    @Test
    fun freshCardImportsAsPublicOnlyCardBackedRow() = runBlocking {
        val (db, repo, _) = temp()
        val gen = generate("fresh-card@pgpony.app")
        val (primaryFp, subFp) = ringFingerprints(gen.armoredPublicKey)

        val entity = repo.importCardKey(cardInfoFor(sigFp = primaryFp, decFp = subFp))

        assertEquals(1, repo.count())
        assertTrue(entity.isCardBacked)
        assertFalse(entity.isKeyPair, "no on-card secret material is stored")
        assertEquals("01020304", entity.cardSerial)
        assertEquals(primaryFp, entity.cardSigFingerprint)
        assertNull(repo.exportArmoredPrivateKey(entity.fingerprint), "no secret written")
        db.close()
    }

    @Test
    fun generatedCardKeyStoresPublicCertAndIsUsableAsRecipient() = runBlocking {
        val (db, repo, _) = temp()
        // Stand in for on-card generation: a real key's binary transferable public key +
        // the post-generation card state carrying its fingerprints.
        val gen = generate("cardgen@pgpony.app")
        val (primaryFp, subFp) = ringFingerprints(gen.armoredPublicKey)

        val entity = repo.importGeneratedCardKey(gen.publicKeyData, cardInfoFor(primaryFp, subFp))

        assertTrue(entity.isCardBacked)
        assertNotNull(
            entity.armoredPublicKey,
            "the generated public certificate must be stored (D7 Fix — the merge path used to " +
                "no-op when the card row had no prior material, leaving the key unusable)"
        )
        assertNotNull(
            repo.loadPublicKeyRing(entity.fingerprint),
            "a card-generated key must load as a recipient / verify key"
        )
        assertEquals("cardgen@pgpony.app", entity.userEmail, "row named from the generated UID")
        db.close()
    }

    @Test
    fun importingACertOntoAPairedCardRowStoresTheArmor() = runBlocking {
        val (db, repo, _) = temp()
        val gen = generate("pair-then-import@pgpony.app")
        val (primaryFp, subFp) = ringFingerprints(gen.armoredPublicKey)
        // Pair a blank card row first (no material), THEN import its public cert — the same
        // no-prior-material path the D7 fix covers.
        repo.importCardKey(cardInfoFor(primaryFp, subFp))
        assertNull(repo.byFingerprint(primaryFp)!!.armoredPublicKey, "pairing stores no material")

        val res = repo.importArmoredKeyDetailed(gen.armoredPublicKey)
        assertEquals(ImportResolution.MERGED_NEW_MATERIAL, res)
        assertNotNull(repo.loadPublicKeyRing(primaryFp), "cert now stored on the card row")
        assertNotNull(repo.byFingerprint(primaryFp)!!.armoredPublicKey)
        db.close()
    }

    @Test
    fun importCardKeyLinksOntoAnExistingCertRow() = runBlocking {
        val (db, repo, _) = temp()
        val gen = generate("link-card@pgpony.app")
        val (primaryFp, subFp) = ringFingerprints(gen.armoredPublicKey)
        // The user already imported the public certificate.
        repo.importArmoredKeyDetailed(gen.armoredPublicKey)
        assertEquals(1, repo.count())
        assertFalse(repo.byFingerprint(primaryFp)!!.isCardBacked)

        // Pairing the card stamps card fields onto that SAME row — no duplicate.
        val linked = repo.importCardKey(cardInfoFor(sigFp = primaryFp, decFp = subFp))
        assertEquals(1, repo.count(), "linked, not duplicated")
        assertTrue(linked.isCardBacked)
        assertEquals(primaryFp, linked.fingerprint)
        // The public armor the cert brought is still there (encrypt-to-card needs it).
        assertNotNull(repo.exportArmoredPublicKey(primaryFp))
        db.close()
    }

    @Test
    fun subkeyScanFindsTheOwningEntity() = runBlocking {
        val (db, repo, _) = temp()
        val gen = generate("subkey-scan@pgpony.app")
        val (primaryFp, subFp) = ringFingerprints(gen.armoredPublicKey)
        repo.importArmoredKeyDetailed(gen.armoredPublicKey)

        // The A1 mechanism: a card whose slot carries only a SUBKEY fingerprint still links
        // onto the owning keyring row (offline-primary layouts).
        val bySub = repo.findEntityBySubkeyFingerprint(listOf(subFp))
        assertNotNull(bySub)
        assertEquals(primaryFp, bySub.fingerprint)
        assertNull(repo.findEntityBySubkeyFingerprint(listOf("00".repeat(20))), "no false match")
        db.close()
    }

    // ── Decrypt routing ─────────────────────────────────────────────────

    @Test
    fun matchCardDecryptKeyRoutesAMessageToThePairedCard() = runBlocking {
        val (db, repo, _) = temp()
        val gen = generate("route@pgpony.app")
        val (primaryFp, subFp) = ringFingerprints(gen.armoredPublicKey)
        // Pair the key as card-backed (import cert first so armor is present, then link).
        repo.importArmoredKeyDetailed(gen.armoredPublicKey)
        repo.importCardKey(cardInfoFor(sigFp = primaryFp, decFp = subFp))

        // A message encrypted to that key.
        val ring = repo.loadPublicKeyRing(primaryFp)!!
        val armored = crypto.encryptMessage("hello card", listOf(ring), null, null)

        val match = DesktopCardOps.matchCardDecryptKey(armored.toByteArray(Charsets.UTF_8), repo)
        assertNotNull(match, "the paired card-backed row should match the PKESK")
        assertEquals(primaryFp, match.entity.fingerprint)

        // A message to an UNPAIRED software key doesn't route to the card.
        val other = generate("other@pgpony.app")
        repo.importArmoredKeyDetailed(other.armoredPrivateKey)
        val otherRing = repo.loadPublicKeyRing(other.fingerprint)!!
        val toOther = crypto.encryptMessage("nope", listOf(otherRing), null, null)
        assertNull(DesktopCardOps.matchCardDecryptKey(toOther.toByteArray(Charsets.UTF_8), repo))
        db.close()
    }

    @Test
    fun signsOnCardPredicate() = runBlocking {
        val (db, repo, _) = temp()
        val gen = generate("signs@pgpony.app")
        val (primaryFp, subFp) = ringFingerprints(gen.armoredPublicKey)
        repo.importArmoredKeyDetailed(gen.armoredPublicKey)
        repo.importCardKey(cardInfoFor(sigFp = primaryFp, decFp = subFp))
        val cardRow = repo.byFingerprint(primaryFp)!!
        assertTrue(DesktopCardOps.signsOnCard(cardRow))

        val soft = generate("soft@pgpony.app")
        repo.importArmoredKeyDetailed(soft.armoredPrivateKey)
        assertFalse(DesktopCardOps.signsOnCard(repo.byFingerprint(soft.fingerprint)))
        assertFalse(DesktopCardOps.signsOnCard(null))
        db.close()
    }

    // ── PIN cache twin ──────────────────────────────────────────────────

    @Test
    fun pinCacheEnableDurationExpirySentinelClear() {
        val node = MemoryPreferences()
        CardPinCache.prefsOverride = node
        try {
            // Default OFF — remember is a no-op, retrieve is null.
            assertFalse(CardPinCache.isEnabled())
            CardPinCache.remember("123456")
            assertNull(CardPinCache.retrieve())

            CardPinCache.setEnabled(true)
            CardPinCache.setDurationSec(300)
            CardPinCache.remember("123456")
            assertEquals("123456", CardPinCache.retrieve())
            assertTrue(CardPinCache.isHolding())
            assertTrue(CardPinCache.remainingMs() in 1..300_000)

            // Sentinel: held with no timer.
            CardPinCache.setDurationSec(CardPinCache.DURATION_UNTIL_CLEARED)
            assertTrue(CardPinCache.isUntilCleared())
            assertEquals(Long.MAX_VALUE, CardPinCache.remainingMs())

            // Clear drops it; toggling off also clears.
            CardPinCache.clear()
            assertNull(CardPinCache.retrieve())
            CardPinCache.setDurationSec(300)
            CardPinCache.remember("123456")
            CardPinCache.setEnabled(false)
            assertNull(CardPinCache.retrieve(), "disabling clears the held PIN")
        } finally {
            CardPinCache.setEnabled(false)
            CardPinCache.clear()
            CardPinCache.prefsOverride = null
        }
    }

    // ── Reader discovery degrades cleanly ───────────────────────────────

    @Test
    fun listReadersNeverThrows() {
        // On CI there's no PC/SC service; listReaders must return empty, not blow up.
        val readers = DesktopCardReader.listReaders()
        assertNotNull(readers)
    }
}
