// DecryptOrderTest.kt
// PGPony Desktop 3.0.0, stage 2 checkpoint 2c: the decrypt order with fallbacks and strict mode
// (Android #34), the cascade rule, the #46 failure wording, signing defaults, and the classical
// subkey of a composite ML-DSA key opening mail (Android 4.6.0 item 21).

package com.pgpony.desktop

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.FallbackPrefs
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.SigningDefaultsEntity
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.runBlocking
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DecryptOrderTest {

    private val pass = "order-passphrase"

    @BeforeTest
    fun hooks() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }
    }

    @AfterTest
    fun unhook() = SettingsStores.uninstall()

    private fun temp(): Triple<PGPDatabase, DesktopKeyRepository, DesktopKeyEdits> {
        val dir = Files.createTempDirectory("pgpony-order-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        return Triple(db, repo, DesktopKeyEdits(repo))
    }

    // ── Pure rules ──

    @Test
    fun orderIsSelectedThenFallbacksThenRestUnlessStrict() = runBlocking {
        val (db, repo, _) = temp()
        val a = repo.generateKey("A", "a@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val b = repo.generateKey("B", "b@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val c = repo.generateKey("C", "c@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val d = repo.generateKey("D", "d@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val all = listOf(a, b, c, d)
        fun fps(list: List<com.pgpony.android.data.PGPKeyEntity>) = list.map { it.userName }

        assertEquals(listOf("A", "B", "C", "D"), fps(DecryptOrder.ordered(null, all, emptyList(), strict = false)))
        assertEquals(listOf("C", "D", "B", "A"), fps(DecryptOrder.ordered(c.fingerprint, all, listOf(d.fingerprint, b.fingerprint), strict = false)))
        assertEquals(listOf("C", "D", "B"), fps(DecryptOrder.ordered(c.fingerprint, all, listOf(d.fingerprint, b.fingerprint), strict = true)))
        assertEquals(listOf("A", "B", "C", "D"), fps(DecryptOrder.ordered("GONE", all, emptyList(), strict = true)), "an unknown key falls back to everything")
        db.close()
    }

    @Test
    fun cascadeTriesEachAloneThenTheWholeList() {
        val seen = mutableListOf<List<Int>>()
        val hit = DecryptOrder.cascade(listOf(1, 2, 3)) { rings ->
            seen += rings
            if (rings == listOf(2)) "two" else error("no")
        }
        assertEquals("two", hit)
        assertEquals(listOf(listOf(1), listOf(2)), seen)

        seen.clear()
        val failure = assertFailsWith<IllegalStateException> {
            DecryptOrder.cascade(listOf(1, 2)) { rings -> seen += rings; error("tried $rings") }
        }
        assertEquals("tried [1, 2]", failure.message, "only the full-list attempt's error propagates")
        assertEquals(listOf(listOf(1), listOf(2), listOf(1, 2)), seen)
    }

    @Test
    fun signingDefaultsPickByContext() = runBlocking {
        val (db, repo, _) = temp()
        val base = repo.generateKey("Base", "base@pgpony.app", KeyAlgorithm.V6_ED25519, null)
        val classic = repo.generateKey("Classic", "classic@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val pq = repo.generateKey("PQ", "pq@pgpony.app", KeyAlgorithm.MLDSA65_ED25519_V6, null)
        val keys = repo.allKeys()
        val row = SigningDefaultsEntity(
            base.fingerprint,
            pqcSignerFingerprint = pq.fingerprint,
            classicalSignerFingerprint = classic.fingerprint,
            signOnlySignerFingerprint = null
        )
        assertEquals(pq.fingerprint, SigningDefaults.pick(base, row, listOf(pq), false, keys).fingerprint, "all post-quantum recipients")
        assertEquals(classic.fingerprint, SigningDefaults.pick(base, row, listOf(pq, classic), false, keys).fingerprint, "any classical recipient")
        assertEquals(base.fingerprint, SigningDefaults.pick(base, row, emptyList(), true, keys).fingerprint, "unset sign-only keeps the key")
        assertEquals(base.fingerprint, SigningDefaults.pick(base, row.copy(fingerprint = classic.fingerprint), listOf(pq), false, keys).fingerprint, "a row for another key is ignored")
        assertEquals(base.fingerprint, SigningDefaults.pick(base, row.copy(pqcSignerFingerprint = "GONE"), listOf(pq), false, keys).fingerprint, "a missing pick keeps the key")

        repo.db.signingDefaultsDao().upsert(row.copy(signOnlySignerFingerprint = classic.fingerprint))
        assertEquals(classic.fingerprint, repo.signerAfterDefaults(base, emptyList(), signOnly = true).fingerprint, "read from the table")
        db.close()
    }

    // ── Against real keys ──

    @Test
    fun strictModeLimitsTheDecryptAndSaysWhy() = runBlocking {
        val (db, repo, edits) = temp()
        val alpha = repo.generateKey("Alpha", "alpha@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val beta = repo.generateKey("Beta", "beta@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val gamma = repo.generateKey("Gamma", "gamma@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val toGamma = repo.encryptText("for gamma", listOf(repo.loadPublicKeyRing(gamma.fingerprint)!!), null, null)

        edits.setFallbacks(alpha.fingerprint, listOf(beta.fingerprint))
        assertEquals("for gamma", repo.decryptText(toGamma, null, alpha.fingerprint).plaintext, "not strict: every key still goes along")

        FallbackPrefs.setStrict(alpha.fingerprint, true)
        val k = repo.decryptKeys(alpha.fingerprint)
        assertEquals(listOf(alpha.fingerprint, beta.fingerprint), k.keys.map { it.fingerprint })
        val failure = runCatching { repo.decryptText(toGamma, null, alpha.fingerprint) }.exceptionOrNull()
        assertNotNull(failure, "strict: Gamma is not tried")
        val explained = repo.explainDecryptFailure(
            { com.pgpony.android.crypto.PGPCryptoService.shared.recipientKeyIDs(toGamma) }, alpha.fingerprint, failure
        )
        assertTrue(explained.message!!.contains("Alpha"), "names the selected key that is not a recipient: ${explained.message}")
        db.close()
    }

    @Test
    fun compositeKeysClassicalSubkeyOpensMail() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("ML Mail", "mlmail@pgpony.app", KeyAlgorithm.MLDSA65_ED25519_V6, pass)
        edits.addSubkey(k.fingerprint, AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT), null, pass)
        val classical = repo.loadCompositeClassicalDecryptionRing(k.fingerprint)
        assertNotNull(classical, "the classical subkey comes out as its own ring")
        // The carrier ring has no bindings (CompositeKeyFacade.classicalDecryptionRing), so the
        // app's encrypt path refuses it. Encrypt straight to the subkey the way a classical
        // client that read the certificate would.
        val subkey = classical.publicKeys.asSequence().last()
        val armored = encryptToKey(subkey, "to the X25519 subkey")
        assertEquals("to the X25519 subkey", repo.decryptText(armored, pass).plaintext)
        db.close()
    }

    private fun encryptToKey(key: PGPPublicKey, text: String): String {
        val data = text.toByteArray(Charsets.UTF_8)
        val gen = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(SecureRandom())
        )
        gen.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(key))
        val bout = ByteArrayOutputStream()
        ArmoredOutputStream(bout).use { armor ->
            gen.open(armor, ByteArray(1 shl 12)).use { enc ->
                PGPLiteralDataGenerator().open(enc, PGPLiteralData.UTF8, PGPLiteralData.CONSOLE, data.size.toLong(), Date())
                    .use { it.write(data) }
            }
        }
        return bout.toString(Charsets.UTF_8)
    }
}
