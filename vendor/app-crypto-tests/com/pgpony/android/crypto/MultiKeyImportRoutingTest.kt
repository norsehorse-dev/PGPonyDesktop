// MultiKeyImportRoutingTest.kt
// PGPony Android — 4.0.4
//
// Regression test for the multi-key import bug.
//
// THE BUG
//
// KeyringViewModel.confirmImportPreview routed on the number of ARMOR
// BLOCKS in the file:
//
//     val blocks = repo.splitArmoredKeyBlocks(preview.armoredText)
//     if (blocks.size > 1) { ...import all, report a summary... }
//     ...otherwise import exactly one key...
//
// But `gpg --export alice bob carol` does not emit three armor blocks. It
// emits ONE block containing three key rings — and a binary export gets
// wrapped into a single block by previewKeyBytes before it ever reaches
// the routing. So the ordinary way to hand PGPony several keys scored
// blocks.size == 1, took the single-key branch, imported only the first
// ring, and reported "Public key imported" as though nothing had been
// dropped.
//
// The repository already knew how to explode a block into per-ring armor
// (importAllArmoredKeysDetailed did exactly that) — it was simply never
// reached for this shape of file. The fix routes on
// KeyRepository.countKeyRings, which shares its explode step with the
// importer.
//
// WHY THIS TESTS A MIRROR AND NOT KeyRepository ITSELF
//
// KeyRepository cannot be built in a JVM unit test: it needs a
// SecureKeyStore, which needs an Android Context and
// EncryptedSharedPreferences. So explodePerRing() below is a copy of the
// repository's private method of the same name, and the two must be kept
// in step. Everything it calls — the block regex and
// PGPCryptoService.explodeToArmoredKeys — is the real production code.
//
// WHAT THIS PINS
//
// 1. A single-block multi-key export reports one block but N rings. If the
//    block count ever becomes the routing signal again, this fails.
// 2. Both levels of the split are load-bearing. explodeToArmoredKeys alone
//    cannot handle concatenated blocks, and the block regex alone cannot
//    handle multiple rings in one block. Neither is redundant.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class MultiKeyImportRoutingTest {

    private val crypto = PGPCryptoService.shared

    // Mirrors KeyRepository.armoredKeyBlockRegex (private there).
    private val armoredKeyBlockRegex = Regex(
        "-----BEGIN PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----" +
            ".*?" +
            "-----END PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----",
        RegexOption.DOT_MATCHES_ALL
    )

    /** The OLD routing signal — kept to document why it was wrong. */
    private fun blockCount(text: String) = armoredKeyBlockRegex.findAll(text).count()

    /** Mirrors KeyRepository.explodePerRing — the NEW routing signal. */
    private fun explodePerRing(armoredText: String): List<String> {
        val blocks = armoredKeyBlockRegex.findAll(armoredText).map { it.value }.toList()
            .ifEmpty { listOf(armoredText) }
        val perRing = ArrayList<String>()
        for (block in blocks) {
            val rings = crypto.explodeToArmoredKeys(block.toByteArray(Charsets.UTF_8))
            if (rings.isEmpty()) perRing.add(block) else perRing.addAll(rings)
        }
        return perRing
    }

    private fun newPublicKey(email: String): ByteArray =
        crypto.generateKeyPair(
            name = "Test ${email.substringBefore('@')}",
            email = email,
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = null
        ).publicKeyData

    private fun newArmoredKey(name: String, email: String): String =
        crypto.generateKeyPair(name, email, KeyAlgorithm.ED25519_CV25519, null).armoredPublicKey

    /** What `gpg --export a b c --armor` produces: one block, three rings. */
    private fun oneArmorBlockWith(vararg keys: ByteArray): String {
        val combined = keys.reduce { a, b -> a + b }
        val bos = ByteArrayOutputStream()
        ArmoredOutputStream(bos).use { it.write(combined) }
        return bos.toString("UTF-8")
    }

    // ── The bug ────────────────────────────────────────────────────────

    @Test
    fun `single armor block holding three rings reports one block but three rings`() {
        val armored = oneArmorBlockWith(
            newPublicKey("alice@example.com"),
            newPublicKey("bob@example.com"),
            newPublicKey("carol@example.com")
        )

        assertEquals(
            "gpg emits ONE armor block for a multi-key export; routing on " +
                "this number sends the file down the single-key path",
            1,
            blockCount(armored)
        )
        assertEquals("all three rings must reach the importer", 3, explodePerRing(armored).size)
    }

    @Test
    fun `binary export of several keys explodes into one ring each`() {
        // `gpg --export a b` with no --armor. previewKeyBytes wraps this in
        // a single armor block before routing, so it hits the same path.
        val binary = newPublicKey("dave@example.com") + newPublicKey("erin@example.com")
        assertEquals(2, crypto.explodeToArmoredKeys(binary).size)

        val wrapped = ByteArrayOutputStream().also { bos ->
            ArmoredOutputStream(bos).use { it.write(binary) }
        }.toString("UTF-8")

        assertEquals(1, blockCount(wrapped))
        assertEquals(2, explodePerRing(wrapped).size)
    }

    // ── Both levels of the split are load-bearing ──────────────────────

    @Test
    fun `concatenated armor blocks need the block split, not just the ring explode`() {
        val concatenated = newArmoredKey("Frank", "frank@example.com") + "\n" +
            newArmoredKey("Grace", "grace@example.com")

        assertEquals(2, blockCount(concatenated))

        // This is the assertion that caught my own first draft of this test.
        // explodeToArmoredKeys wraps the bytes in a single ArmoredInputStream,
        // which stops reading at the first END marker — so handed the whole
        // concatenated text it sees ONE ring and silently ignores the rest.
        // That is precisely why explodePerRing splits on BEGIN/END first and
        // explodes each block separately. Drop the split and this file loses
        // every key after the first.
        assertEquals(
            "explodeToArmoredKeys alone cannot see past the first armor block",
            1,
            crypto.explodeToArmoredKeys(concatenated.toByteArray(Charsets.UTF_8)).size
        )

        assertEquals("with the block split, both keys are found", 2, explodePerRing(concatenated).size)
    }

    @Test
    fun `a single key still counts as exactly one ring`() {
        // The overwhelmingly common import. It must not get routed into the
        // multi-key summary path, which would change its success message and
        // skip the "already in keyring" dialog.
        val one = newArmoredKey("Heidi", "heidi@example.com")
        assertEquals(1, blockCount(one))
        assertEquals(1, explodePerRing(one).size)
    }

    @Test
    fun `unparseable text degrades to one ring rather than vanishing`() {
        // explodeToArmoredKeys returns an empty list on any parse failure.
        // explodePerRing must fall back to passing the block through whole,
        // so a malformed paste still reaches the importer and produces a
        // real error instead of a silent success importing nothing.
        val junk = "not a key at all"
        assertEquals(0, crypto.explodeToArmoredKeys(junk.toByteArray(Charsets.UTF_8)).size)
        assertEquals(1, explodePerRing(junk).size)
    }

    @Test
    fun `exploded rings are individually parseable and distinct`() {
        val armored = oneArmorBlockWith(
            newPublicKey("ivan@example.com"),
            newPublicKey("judy@example.com")
        )
        val rings = explodePerRing(armored)
        assertEquals(2, rings.size)

        val fingerprints = rings.map { crypto.importArmoredKey(it).fingerprint }
        assertTrue("each exploded ring must parse", fingerprints.all { it.isNotBlank() })
        assertEquals("the two rings must be distinct keys", 2, fingerprints.toSet().size)
    }
}
