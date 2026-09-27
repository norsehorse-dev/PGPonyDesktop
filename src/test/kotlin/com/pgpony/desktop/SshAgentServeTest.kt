// SshAgentServeTest.kt
// PGPony Desktop 3.0.0, stage 3 checkpoint 3b (plan section 5): what the agent serves and how
// it signs, against a real keyring. Only a dedicated authentication subkey is served; a
// composite ML-DSA key's classical auth subkey is served; RSA keeps SHA-1 ssh-rsa for a request
// with no SHA-2 flag (plan Q10); Key Detail's authorized_keys line.

package com.pgpony.desktop

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SshAgentServeTest {

    @BeforeTest
    fun hooks() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }
    }

    @AfterTest
    fun unhook() = SettingsStores.uninstall()

    private fun temp(): Triple<PGPDatabase, DesktopKeyRepository, DesktopKeyEdits> {
        val dir = Files.createTempDirectory("pgpony-agent-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        return Triple(db, repo, DesktopKeyEdits(repo))
    }

    private fun sigName(blob: ByteArray): Pair<String, ByteArray> {
        val r = SshWire.Reader(blob)
        return String(r.string()) to r.string()
    }

    @Test
    fun onlyADedicatedAuthSubkeyIsServed() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("Agent", "agent@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        assertTrue(SshAgentKeys.identities(repo).isEmpty(), "a primary that signs and certifies is never served")

        edits.addSshAuthSubkeyAtGeneration(k.fingerprint, k.algorithm, null, null)
        val ids = SshAgentKeys.identities(repo)
        assertEquals(1, ids.size)

        val data = "session-id-and-request".toByteArray()
        val (name, sig) = sigName(assertNotNull(SshAgentKeys.sign(repo, ids.single().identity.blob, data, 0)))
        assertEquals("ssh-ed25519", name)
        val point = SshWire.Reader(ids.single().identity.blob).let { it.string(); it.string() }
        val verifier = Ed25519Signer().apply { init(false, Ed25519PublicKeyParameters(point, 0)) }
        verifier.update(data, 0, data.size)
        assertTrue(verifier.verifySignature(sig), "a real Ed25519 signature by the served key")

        val line = assertNotNull(repo.sshPublicKey(repo.byFingerprint(k.fingerprint)!!))
        assertTrue(line.line.startsWith("ssh-ed25519 ") && line.line.endsWith(" agent@pgpony.app"), line.line)
        assertTrue(line.fingerprint.startsWith("SHA256:"))
        db.close()
    }

    @Test
    fun compositeKeysClassicalAuthSubkeyIsServed() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("PQ Agent", "pqagent@pgpony.app", KeyAlgorithm.MLDSA65_ED25519_V6, null)
        edits.addSubkey(k.fingerprint, AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH), null, null)
        val ids = SshAgentKeys.identities(repo)
        assertEquals(1, ids.size, "the Ed25519 auth subkey on the ML-DSA key")
        assertNotNull(SshAgentKeys.sign(repo, ids.single().identity.blob, "x".toByteArray(), 0))
        db.close()
    }

    @Test
    fun rsaKeepsSha1WhenNoFlagIsSet() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("RSA Agent", "rsaagent@pgpony.app", KeyAlgorithm.RSA_2048, null)
        edits.addSshAuthSubkeyAtGeneration(k.fingerprint, k.algorithm, null, null)
        val blob = SshAgentKeys.identities(repo).single().identity.blob
        assertEquals("ssh-rsa", String(SshWire.Reader(blob).string()), "an RSA subkey to match an RSA key")
        val data = "challenge".toByteArray()
        assertEquals("ssh-rsa", sigName(SshAgentKeys.sign(repo, blob, data, 0)!!).first)
        assertEquals("rsa-sha2-256", sigName(SshAgentKeys.sign(repo, blob, data, SshWire.SSH_AGENT_RSA_SHA2_256)!!).first)
        assertEquals("rsa-sha2-512", sigName(SshAgentKeys.sign(repo, blob, data, SshWire.SSH_AGENT_RSA_SHA2_512)!!).first)
        db.close()
    }
}
