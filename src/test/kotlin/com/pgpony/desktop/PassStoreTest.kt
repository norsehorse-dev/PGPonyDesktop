// PassStoreTest.kt
// D8 validation. Three layers, all offline and deterministic:
//
//   1. The store layer (DesktopPassStore, java.nio) against a fixture store built on a temp
//      directory — walk shape and ordering, dotfile/.git/.gpg-id exclusion, nearest-ancestor
//      .gpg-id resolution, search, and the path-traversal defence the SAF version never needed.
//   2. The prefs twins (PassStorePrefs, DesktopPassSettings, DesktopClipboard) on an in-memory
//      Preferences node — no on-disk side effects, reusing MemoryPreferences from
//      KeyServerDirectoryTest.
//   3. The end-to-end decrypt: a real generated keypair, a real OpenPGP-encrypted entry file,
//      routed by PassDecryptCoordinator and parsed by the VENDORED-LIVE PassEntryParser — the
//      same parser bytes the Android app runs, so a parity break here is a compile break there.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.pass.PassDecryptCoordinator
import com.pgpony.android.crypto.pass.PassEntryParser
import com.pgpony.android.crypto.pass.PassNode
import com.pgpony.android.crypto.pass.PassRoute
import com.pgpony.android.crypto.pass.PassStorePrefs
import com.pgpony.android.crypto.pass.PassStoreRef
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PassStoreTest {

    private val crypto = PGPCryptoService.shared
    private val windows = System.getProperty("os.name").lowercase().contains("win")

    private lateinit var storePrefs: MemoryPreferences
    private lateinit var settingsPrefs: MemoryPreferences
    private lateinit var clipboardPrefs: MemoryPreferences

    @BeforeTest
    fun hookPrefs() {
        storePrefs = MemoryPreferences()
        settingsPrefs = MemoryPreferences()
        clipboardPrefs = MemoryPreferences()
        PassStorePrefs.prefsOverride = storePrefs
        DesktopPassSettings.prefsOverride = settingsPrefs
        DesktopClipboard.prefsOverride = clipboardPrefs
    }

    @AfterTest
    fun unhookPrefs() {
        PassStorePrefs.prefsOverride = null
        DesktopPassSettings.prefsOverride = null
        DesktopClipboard.prefsOverride = null
    }

    // ── Fixture ─────────────────────────────────────────────────────────

    /**
     * A store shaped like a real one:
     *
     *   .gpg-id            root@pgpony.app
     *   .git/HEAD          (must be skipped — dotfolder)
     *   README.md          (must be skipped — not .gpg)
     *   bank.gpg
     *   Email.gpg
     *   My Bank.gpg        (a space in the name — legal, and it must stay readable)
     *   personal/note.gpg
     *   Work/.gpg-id       work@pgpony.app
     *   Work/vpn.gpg
     *   Work/Sub/thing.gpg
     */
    private fun fixture(): Path {
        val root = Files.createTempDirectory("pgpony-pass-test")
        fun write(rel: String, text: String) {
            val p = root.resolve(rel)
            Files.createDirectories(p.parent)
            Files.write(p, text.toByteArray())
        }
        write(".gpg-id", "root@pgpony.app\n")
        write(".git/HEAD", "ref: refs/heads/main\n")
        write("README.md", "not an entry\n")
        write("bank.gpg", "ciphertext")
        write("Email.gpg", "ciphertext")
        write("My Bank.gpg", "ciphertext")
        write("personal/note.gpg", "ciphertext")
        write("Work/.gpg-id", "work@pgpony.app\nsecond@pgpony.app\n")
        write("Work/vpn.gpg", "ciphertext")
        write("Work/Sub/thing.gpg", "ciphertext")
        return root
    }

    private fun refFor(root: Path): PassStoreRef = DesktopPassStore.buildRef(root)

    // ── The walk ────────────────────────────────────────────────────────

    @Test
    fun walkPutsFoldersBeforeEntriesAndSkipsDotfilesAndNonGpg() {
        val root = fixture()
        val tree = assertNotNull(DesktopPassStore.walkTree(refFor(root)))

        val names = tree.children.map {
            when (it) {
                is PassNode.Folder -> "d:" + it.folderName
                is PassNode.Entry -> "e:" + it.entryName
            }
        }
        // Folders first (case-insensitively sorted), then entries (likewise). No .git, no README.
        assertEquals(
            listOf("d:personal", "d:Work", "e:bank", "e:Email", "e:My Bank"),
            names
        )
    }

    @Test
    fun entryNamesDropTheGpgSuffixAndCarryTheirRelativePath() {
        val root = fixture()
        val tree = assertNotNull(DesktopPassStore.walkTree(refFor(root)))
        val nested = DesktopPassStore.flatten(tree).single { it.entryName == "thing" }
        assertEquals("Work/Sub/thing", nested.relativePath)
    }

    @Test
    fun folderAtNavigatesByPathAndMissesCleanly() {
        val root = fixture()
        val tree = assertNotNull(DesktopPassStore.walkTree(refFor(root)))
        assertEquals("Sub", assertNotNull(DesktopPassStore.folderAt(tree, "Work/Sub")).folderName)
        assertEquals(tree, DesktopPassStore.folderAt(tree, ""))
        assertNull(DesktopPassStore.folderAt(tree, "Work/Nope"))
    }

    @Test
    fun searchRequiresEveryTermSomewhereInThePath() {
        val root = fixture()
        val tree = assertNotNull(DesktopPassStore.walkTree(refFor(root)))

        assertEquals(
            listOf("Work/Sub/thing"),
            DesktopPassStore.search(tree, "work thing").map { it.relativePath }
        )
        // Case-insensitive, and a term may match the folder rather than the entry.
        assertEquals(2, DesktopPassStore.search(tree, "WORK").size)
        assertTrue(DesktopPassStore.search(tree, "work nonesuch").isEmpty())
        assertTrue(DesktopPassStore.search(tree, "   ").isEmpty())
    }

    // ── .gpg-id resolution ──────────────────────────────────────────────

    @Test
    fun nearestAncestorGpgIdWins() {
        val root = fixture()
        val ref = refFor(root)

        assertEquals(listOf("root@pgpony.app"), ref.rootGpgIds)
        assertEquals(
            listOf("work@pgpony.app", "second@pgpony.app"),
            DesktopPassStore.recipientsForEntry(ref, "Work/vpn")
        )
        // Work/Sub has no .gpg-id of its own — it inherits Work's, not the root's.
        assertEquals(
            listOf("work@pgpony.app", "second@pgpony.app"),
            DesktopPassStore.recipientsForEntry(ref, "Work/Sub/thing")
        )
        assertEquals(
            listOf("root@pgpony.app"),
            DesktopPassStore.recipientsForEntry(ref, "personal/note")
        )
        assertEquals(listOf("root@pgpony.app"), DesktopPassStore.recipientsForEntry(ref, "bank"))
    }

    // ── Traversal defence ───────────────────────────────────────────────

    @Test
    fun pathsThatEscapeTheStoreAreRefused() {
        val root = fixture()
        val ref = refFor(root)

        // A sibling file that really exists — proving the refusal isn't just "file not found".
        val outside = root.parent.resolve("outside-${root.fileName}.gpg")
        Files.write(outside, "secret".toByteArray())

        assertNull(DesktopPassStore.resolveLeaf(root, "../outside-${root.fileName}"))
        assertNull(DesktopPassStore.resolveLeaf(root, "Work/../../outside-${root.fileName}"))
        assertNull(DesktopPassStore.resolveLeaf(root, ".."))
        assertNull(DesktopPassStore.resolveLeaf(root, "Work//vpn"))       // empty segment
        assertNull(DesktopPassStore.resolveLeaf(root, "Work\\vpn"))       // backslash separator
        assertNull(DesktopPassStore.readEntryBytes(ref, "../outside-${root.fileName}"))

        Files.deleteIfExists(outside)
    }

    @Test
    fun ordinaryEntryNamesWithSpacesStillResolve() {
        val root = fixture()
        val ref = refFor(root)

        assertNotNull(DesktopPassStore.resolveLeaf(root, "My Bank"))
        assertEquals("ciphertext", String(assertNotNull(DesktopPassStore.readEntryBytes(ref, "My Bank"))))
        assertEquals("ciphertext", String(assertNotNull(DesktopPassStore.readEntryBytes(ref, "Work/Sub/thing"))))
        // A colon is legal in a POSIX filename and must not be treated as suspicious.
        if (!windows) assertNotNull(DesktopPassStore.resolveLeaf(root, "My Bank: checking"))
    }

    @Test
    fun aMissingOrUnresolvableStoreReadsAsNullRatherThanThrowing() {
        val ghost = PassStoreRef(
            id = "ghost", displayName = "Gone",
            treeUri = "file:///nonexistent-pgpony-store", rootGpgIds = emptyList()
        )
        assertNull(DesktopPassStore.walkTree(ghost))
        assertNull(DesktopPassStore.resolveRoot(ghost))
        assertNull(DesktopPassStore.readEntryBytes(ghost, "anything"))
        assertEquals(emptyList(), DesktopPassStore.recipientsForEntry(ghost, "anything"))
    }

    // ── buildRef ────────────────────────────────────────────────────────

    @Test
    fun buildRefReadsRootIdsAndNamesTheConventionalDotFolder() {
        val root = fixture()
        val named = DesktopPassStore.buildRef(root)
        assertEquals(root.fileName.toString(), named.displayName)
        assertEquals(listOf("root@pgpony.app"), named.rootGpgIds)

        val dotted = Files.createDirectories(root.resolve(".password-store"))
        assertEquals("Password Store", DesktopPassStore.buildRef(dotted).displayName)

        // The stored location round-trips through the file: URI slot.
        assertEquals(
            root.toAbsolutePath().normalize(),
            assertNotNull(DesktopPassStore.pathOf(named.treeUri))
        )
    }

    // ── Prefs twins ─────────────────────────────────────────────────────

    @Test
    fun storeListRoundTripsAndUpsertsByTreeUri() {
        assertEquals(emptyList(), PassStorePrefs.load())

        val a = PassStoreRef("a", "Alpha", "file:///stores/alpha", listOf("a@pgpony.app"))
        val b = PassStoreRef("b", "Beta", "file:///stores/beta", emptyList())
        PassStorePrefs.save(listOf(a, b))

        val loaded = PassStorePrefs.load()
        assertEquals(listOf("Alpha", "Beta"), loaded.map { it.displayName })
        assertEquals(listOf("a@pgpony.app"), loaded.first().rootGpgIds)

        // Re-picking the same folder replaces in place (matched by treeUri, not id) and lands last.
        val aAgain = PassStoreRef("a2", "Alpha renamed", "file:///stores/alpha", emptyList())
        val after = PassStorePrefs.upsert(aAgain)
        assertEquals(listOf("Beta", "Alpha renamed"), after.map { it.displayName })
        assertEquals(after, PassStorePrefs.load())

        assertEquals(listOf("Alpha renamed"), PassStorePrefs.remove("b").map { it.displayName })
        assertEquals(emptyList(), PassStorePrefs.remove("a2"))
    }

    @Test
    fun corruptStoreBlobReadsAsEmptyRatherThanThrowing() {
        storePrefs.put(PassStorePrefs.KEY_STORES, "{not json at all")
        assertEquals(emptyList(), PassStorePrefs.load())
    }

    @Test
    fun theSurfaceIsOffUntilAskedFor() {
        assertTrue(!DesktopPassSettings.enabled(), "off by default, matching Android")
        DesktopPassSettings.setEnabled(true)
        assertTrue(DesktopPassSettings.enabled())
        DesktopPassSettings.setEnabled(false)
        assertTrue(!DesktopPassSettings.enabled())
    }

    @Test
    fun clipboardTimeoutDefaultsMatchAndroidAndAreClamped() {
        assertEquals(60, DesktopClipboard.clearSeconds())
        assertTrue(DesktopClipboard.autoClear(), "auto-clear on by default")

        DesktopClipboard.setClearSeconds(1)
        assertEquals(5, DesktopClipboard.clearSeconds(), "a 1s timer clears before a paste")
        DesktopClipboard.setClearSeconds(99_999)
        assertEquals(600, DesktopClipboard.clearSeconds())
        DesktopClipboard.setClearSeconds(90)
        assertEquals(90, DesktopClipboard.clearSeconds())

        DesktopClipboard.setAutoClear(false)
        assertTrue(!DesktopClipboard.autoClear())
    }

    // ── The parser (vendored LIVE — the same bytes Android compiles) ─────

    @Test
    fun parserSplitsPasswordFieldsOtpAndNotes() {
        val content = PassEntryParser.parse(
            """
            hunter2
            login: kevin@pgpony.app
            url: https://pgpony.app/login
            otpauth://totp/PGPony:kevin?secret=ABCDEF&issuer=PGPony

            recovery codes are in the safe
            """.trimIndent()
        )

        assertEquals("hunter2", content.password)
        assertEquals(listOf("login", "url"), content.fields.map { it.key })
        assertEquals("kevin@pgpony.app", content.fields.first().value)
        assertEquals("https://pgpony.app/login", content.fields[1].value)
        assertEquals("otpauth://totp/PGPony:kevin?secret=ABCDEF&issuer=PGPony", content.otpauth)
        assertEquals(listOf("recovery codes are in the safe"), content.extraLines)
    }

    @Test
    fun parserToleratesCrlfAndABareUrlSecondLine() {
        val content = PassEntryParser.parse("s3cret\r\nhttps://example.test/login\r\nuser: kevin\r\n")
        assertEquals("s3cret", content.password)
        // A bare URL is not a "https" field — the value-side "//" marks it freeform.
        assertEquals(listOf("user"), content.fields.map { it.key })
        assertTrue(content.extraLines.contains("https://example.test/login"))
    }

    // ── End to end ──────────────────────────────────────────────────────

    private fun repo(tag: String): Pair<com.pgpony.android.data.PGPDatabase, DesktopKeyRepository> {
        val dir = Files.createTempDirectory("pgpony-pass-repo-$tag")
        val db = Db.open(dir.resolve("pgpony.db"))
        return db to DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
    }

    @Test
    fun aSoftwareKeyEntryRoutesDecryptsAndParses() = runBlocking {
        val (db, repo) = repo("mine")
        val me = repo.generateKey("Pass Owner", "pass@pgpony.app", KeyAlgorithm.ED25519_CV25519, "test-passphrase")

        val plaintext = "hunter2\nlogin: kevin\notpauth://totp/x?secret=AB\n"
        val ciphertext = crypto.encrypt(
            data = plaintext.toByteArray(),
            recipientPublicKeys = listOf(repo.loadPublicKeyRing(me.fingerprint)!!),
            armor = false
        )

        val root = fixture()
        Files.write(root.resolve("Email.gpg"), ciphertext)
        val ref = refFor(root)
        val bytes = assertNotNull(DesktopPassStore.readEntryBytes(ref, "Email"))

        val route = PassDecryptCoordinator.route(repo, bytes)
        val software = route as? PassRoute.Software ?: error("expected Software, got $route")

        val content = PassEntryParser.parse(
            PassDecryptCoordinator.decryptSoftware(bytes, software.rings, "test-passphrase")
        )
        assertEquals("hunter2", content.password)
        assertEquals(listOf("login"), content.fields.map { it.key })
        assertEquals("otpauth://totp/x?secret=AB", content.otpauth)
        db.close()
    }

    @Test
    fun anEntryEncryptedToAStrangerHasNoRoute() = runBlocking {
        val (dbMine, mine) = repo("mine2")
        mine.generateKey("Pass Owner", "pass@pgpony.app", KeyAlgorithm.ED25519_CV25519, "test-passphrase")

        val (dbTheirs, theirs) = repo("theirs")
        val stranger = theirs.generateKey("Stranger", "stranger@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)

        val ciphertext = crypto.encrypt(
            data = "nope\n".toByteArray(),
            recipientPublicKeys = listOf(theirs.loadPublicKeyRing(stranger.fingerprint)!!),
            armor = false
        )
        assertEquals(PassRoute.NoMatch, PassDecryptCoordinator.route(mine, ciphertext))

        dbMine.close()
        dbTheirs.close()
    }

    @Test
    fun aWrongPassphraseFailsRatherThanReturningGarbage() = runBlocking {
        val (db, repo) = repo("wrongpass")
        val me = repo.generateKey("Pass Owner", "pass@pgpony.app", KeyAlgorithm.ED25519_CV25519, "test-passphrase")
        val ciphertext = crypto.encrypt(
            data = "hunter2\n".toByteArray(),
            recipientPublicKeys = listOf(repo.loadPublicKeyRing(me.fingerprint)!!),
            armor = false
        )
        val rings = PassDecryptCoordinator.softwareSecretRings(repo)
        assertTrue(rings.isNotEmpty())

        val bad = runCatching { PassDecryptCoordinator.decryptSoftware(ciphertext, rings, "wrong") }
        assertTrue(bad.isFailure, "a wrong passphrase must throw, not silently return")

        val good = PassDecryptCoordinator.decryptSoftware(ciphertext, rings, "test-passphrase")
        assertEquals("hunter2\n", good)
        db.close()
    }
}
