// PortableModeTest.kt
// PGPony Desktop 3.1.0 (plan 3e): portable mode. Covers the folder rule for each build type, the
// --data-dir flag, the macOS translocation lookup, the file-backed preferences store, and the
// rule that a portable copy stores a secret key only with a passphrase.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PortableModeTest {

    // The folder rule is tested with real absolute paths for whichever OS runs the test (a drive
    // root on Windows), so the same tests pass on a Windows checkout too. Only the macOS
    // translocation cases need POSIX paths: they parse `mount` output.
    private val root: Path = Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath().root
    private fun at(rel: String): Path = root.resolve(rel)
    private val posix = java.io.File.separatorChar == '/'

    private fun resolve(
        flag: Path? = null,
        appPath: Path? = null,
        appImage: Path? = null,
        os: String,
        dirs: Set<Path> = emptySet(),
        mounts: String? = null
    ) = PortableMode.resolve(flag, appPath?.toString(), appImage?.toString(), os, { it in dirs }, { mounts })

    // ── The folder rule ───────────────────────────────────────────────────

    @Test
    fun windowsLooksBesidePgponyExe() {
        val r = resolve(appPath = at("E/PGPony/PGPony.exe"), os = "Windows 11", dirs = setOf(at("E/PGPony/PGPony-data")))
        assertEquals(PortableMode.Resolution.Portable(at("E/PGPony/PGPony-data"), fromFlag = false), r)
        assertEquals(PortableMode.Resolution.Installed,
            resolve(appPath = at("Program Files/PGPony/PGPony.exe"), os = "Windows 11"))
    }

    @Test
    fun linuxTarballLooksBesideTheAppFolder() {
        val r = resolve(appPath = at("media/usb/PGPony/bin/PGPony"), os = "Linux", dirs = setOf(at("media/usb/PGPony-data")))
        assertEquals(PortableMode.Resolution.Portable(at("media/usb/PGPony-data"), false), r)
        assertEquals(PortableMode.Resolution.Installed, resolve(appPath = at("opt/pgpony/bin/PGPony"), os = "Linux"))
    }

    @Test
    fun appImageLooksBesideTheAppImageFile() {
        val r = resolve(appPath = at("tmp/.mount_PGPonyXYZ/bin/PGPony"), appImage = at("media/usb/PGPony-x86_64.AppImage"),
            os = "Linux", dirs = setOf(at("media/usb/PGPony-data")))
        assertEquals(PortableMode.Resolution.Portable(at("media/usb/PGPony-data"), false), r)
    }

    @Test
    fun macLooksBesideTheBundle() {
        val r = resolve(appPath = at("Volumes/USB/PGPony.app/Contents/MacOS/PGPony"), os = "Mac OS X",
            dirs = setOf(at("Volumes/USB/PGPony-data")))
        assertEquals(PortableMode.Resolution.Portable(at("Volumes/USB/PGPony-data"), false), r)
        assertEquals(PortableMode.Resolution.Installed,
            resolve(appPath = at("Applications/PGPony.app/Contents/MacOS/PGPony"), os = "Mac OS X"))
    }

    @Test
    fun theFlagBeatsTheFolder() {
        val r = resolve(flag = at("elsewhere/keys"), appPath = at("media/usb/PGPony/bin/PGPony"), os = "Linux",
            dirs = setOf(at("media/usb/PGPony-data")))
        assertEquals(PortableMode.Resolution.Portable(at("elsewhere/keys"), fromFlag = true), r)
    }

    @Test
    fun theFlagIsTakenOutOfTheArguments() {
        val (rest, dir) = PortableMode.takeDataDirFlag(arrayOf("--data-dir", "/x/y", "encrypt", "-r", "a"))
        assertContentEquals(arrayOf("encrypt", "-r", "a"), rest)
        assertEquals(Path.of("/x/y"), dir)
        val (rest2, dir2) = PortableMode.takeDataDirFlag(arrayOf("sign", "--data-dir=/z"))
        assertContentEquals(arrayOf("sign"), rest2)
        assertEquals(Path.of("/z"), dir2)
        val (rest3, dir3) = PortableMode.takeDataDirFlag(arrayOf("version"))
        assertContentEquals(arrayOf("version"), rest3)
        assertNull(dir3)
    }

    // ── macOS App Translocation ───────────────────────────────────────────

    private val translocated =
        Path.of("/private/var/folders/ab/xyz/T/AppTranslocation/1A2B-3C4D/d/PGPony.app/Contents/MacOS/PGPony")

    @Test
    fun aTranslocatedBundleIsFoundThroughTheMountTable() {
        org.junit.Assume.assumeTrue("macOS paths", posix)
        val mounts = """
            /dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
            /dev/disk5s1 on /Volumes/USB (exfat, local, nodev, nosuid, noowners, mounted by me)
            /Volumes/USB/PGPony.app on /private/var/folders/ab/xyz/T/AppTranslocation/1A2B-3C4D (nullfs, local, nodev, nosuid, read-only, nobrowse, mounted by me)
        """.trimIndent()
        val r = resolve(appPath = translocated, os = "Mac OS X", dirs = setOf(Path.of("/Volumes/USB/PGPony-data")), mounts = mounts)
        assertEquals(PortableMode.Resolution.Portable(Path.of("/Volumes/USB/PGPony-data"), false), r)
    }

    @Test
    fun aTranslocatedBundleWithAFolderMountIsFoundToo() {
        org.junit.Assume.assumeTrue("macOS paths", posix)
        val mounts = "/Volumes/USB on /private/var/folders/ab/xyz/T/AppTranslocation/1A2B-3C4D/d (nullfs, local, read-only)"
        val r = resolve(appPath = translocated, os = "Mac OS X", dirs = setOf(Path.of("/Volumes/USB/PGPony-data")), mounts = mounts)
        assertEquals(PortableMode.Resolution.Portable(Path.of("/Volumes/USB/PGPony-data"), false), r)
    }

    @Test
    fun aTranslocatedBundleThatCannotBeTracedIsReported() {
        org.junit.Assume.assumeTrue("macOS paths", posix)
        val r = resolve(appPath = translocated, os = "Mac OS X", mounts = null)
        assertTrue(r is PortableMode.Resolution.TranslocatedUnresolved, r.toString())
    }

    // ── Settings on the drive ─────────────────────────────────────────────

    @Test
    fun settingsRoundTripThroughTheFile() {
        val dir = Files.createTempDirectory("pgpony-portable-prefs")
        val file = dir.resolve("settings.properties")
        val root = FilePreferences.root(file)
        val node = root.node("app/pgpony/desktop")
        node.put("ui_language", "de")
        node.putBoolean("hide_destructive_actions", true)
        node.node("kv").put("tab\tnot", "value with = and : and spaces")
        root.node("app/pgpony/empty")
        node.flush()
        assertTrue(Files.isRegularFile(file))

        val again = FilePreferences.root(file)
        val n2 = again.node("app/pgpony/desktop")
        assertEquals("de", n2.get("ui_language", null))
        assertTrue(n2.getBoolean("hide_destructive_actions", false))
        assertEquals("value with = and : and spaces", n2.node("kv").get("tab\tnot", null))
        assertTrue(again.nodeExists("app/pgpony/empty"), "an empty node is kept")
        assertTrue(n2.childrenNames().contains("kv"))

        n2.remove("ui_language")
        n2.node("kv").removeNode()
        n2.flush()
        val third = FilePreferences.root(file).node("app/pgpony/desktop")
        assertNull(third.get("ui_language", null))
        assertFalse(third.childrenNames().contains("kv"))
        assertTrue(third.getBoolean("hide_destructive_actions", false))
    }

    @Test
    fun aWriteLeavesNoTempFileBehind() {
        val dir = Files.createTempDirectory("pgpony-portable-prefs2")
        val file = dir.resolve("settings.properties")
        val root = FilePreferences.root(file)
        root.node("a").put("k", "v")
        root.flush()
        assertEquals(listOf("settings.properties"), Files.list(dir).use { s -> s.map { it.fileName.toString() }.toList() })
    }

    // ── Secret keys on the drive ──────────────────────────────────────────

    private class Env(val db: com.pgpony.android.data.PGPDatabase, val repo: DesktopKeyRepository, val store: KeyMaterialStore)

    private fun portableEnv(): Env {
        val dir = Files.createTempDirectory("pgpony-portable-keys")
        val db = Db.open(dir.resolve("pgpony.db"))
        val store = KeyMaterialStore(dir.resolve("keys"), requireProtectedSecrets = { true })
        return Env(db, DesktopKeyRepository(db, store), store)
    }

    @Test
    fun theStoreRefusesAnUnprotectedSecretAndTakesAProtectedOne() {
        val dir = Files.createTempDirectory("pgpony-portable-store")
        val store = KeyMaterialStore(dir, requireProtectedSecrets = { true })
        val bare = PGPCryptoService.shared.generateKeyPair("Bare", "bare@example.invalid", KeyAlgorithm.ED25519_CV25519, null)
        assertFailsWith<UnprotectedSecretException> { store.storeSecret(bare.fingerprint, bare.armoredPrivateKey) }
        assertFalse(store.hasSecret(bare.fingerprint))
        val locked = PGPCryptoService.shared.generateKeyPair("Locked", "locked@example.invalid", KeyAlgorithm.ED25519_CV25519, "pass")
        store.storeSecret(locked.fingerprint, locked.armoredPrivateKey)
        assertTrue(store.hasSecret(locked.fingerprint))
    }

    @Test
    fun anUnprotectedImportKeepsThePublicKeyAndWaitsForAPassphrase() = runBlocking {
        val e = portableEnv()
        val bare = PGPCryptoService.shared.generateKeyPair("Bare Import", "bareimport@example.invalid", KeyAlgorithm.ED25519_CV25519, null)
        val report = e.repo.importArmoredText(bare.armoredPrivateKey)
        assertEquals(1, report.inserted)
        val row = e.repo.byFingerprint(bare.fingerprint)
        assertNotNull(row)
        assertFalse(row.isKeyPair, "stored public only")
        assertFalse(e.store.hasSecret(bare.fingerprint))
        val held = e.repo.unprotectedSecrets.value.single()
        assertEquals(bare.fingerprint.uppercase(), held.fingerprint.uppercase())

        assertTrue(e.repo.protectHeldSecret(held, "new-passphrase"))
        assertTrue(e.repo.byFingerprint(bare.fingerprint)!!.isKeyPair)
        assertTrue(e.store.isProtected(e.store.loadSecret(bare.fingerprint)!!), "stored protected")
        assertTrue(e.repo.unprotectedSecrets.value.isEmpty())
        // The new passphrase unlocks it.
        val ring = e.repo.loadSecretKeyRing(bare.fingerprint)!!
        assertTrue(runCatching { PGPCryptoService.shared.changePassphrase(ring, "new-passphrase", "x") }.isSuccess)
        e.db.close()
    }

    @Test
    fun skippingKeepsThePublicKeyOnly() = runBlocking {
        val e = portableEnv()
        val bare = PGPCryptoService.shared.generateKeyPair("Skip Me", "skip@example.invalid", KeyAlgorithm.ED25519_CV25519, null)
        e.repo.importArmoredText(bare.armoredPrivateKey)
        e.repo.dismissUnprotectedSecret(bare.fingerprint)
        assertTrue(e.repo.unprotectedSecrets.value.isEmpty())
        assertFalse(e.repo.byFingerprint(bare.fingerprint)!!.isKeyPair)
        e.db.close()
    }

    @Test
    fun aProtectedImportIsStoredAtOnce() = runBlocking {
        val e = portableEnv()
        val locked = PGPCryptoService.shared.generateKeyPair("Locked Import", "lockedimport@example.invalid", KeyAlgorithm.ED25519_CV25519, "pass")
        e.repo.importArmoredText(locked.armoredPrivateKey)
        assertTrue(e.repo.byFingerprint(locked.fingerprint)!!.isKeyPair)
        assertTrue(e.repo.unprotectedSecrets.value.isEmpty())
        e.db.close()
    }

    @Test
    fun removingAPassphraseIsRefused() = runBlocking {
        val e = portableEnv()
        val locked = PGPCryptoService.shared.generateKeyPair("Keep Locked", "keeplocked@example.invalid", KeyAlgorithm.ED25519_CV25519, "pass")
        e.repo.importArmoredText(locked.armoredPrivateKey)
        assertFailsWith<UnprotectedSecretException> {
            DesktopKeyEdits(e.repo).changePassphrase(locked.fingerprint, "pass", "")
        }
        assertTrue(e.store.isProtected(e.store.loadSecret(locked.fingerprint)!!), "the stored key is unchanged")
        e.db.close()
    }
}
