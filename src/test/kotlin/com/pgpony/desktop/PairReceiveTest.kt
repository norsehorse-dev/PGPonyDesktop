// PairReceiveTest.kt
// PGPony Desktop 3.0.0, F1 pairing: what a receiving keyring does with an item before anything is
// written (docs/PAIRING_PROTOCOL.md, section 6), a backup that arrives by pairing (no trust taken
// from it), the host window's connection handling, and join errors that never escape.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.TrustLevel
import com.pgpony.android.pair.PairException
import com.pgpony.android.pair.PairFailure
import com.pgpony.android.pair.PairItem
import kotlinx.coroutines.runBlocking
import java.net.ConnectException
import java.net.InetAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PairReceiveTest {

    private val threads = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }

    private fun keyring(tag: String): DesktopKeyRepository {
        val dir = Files.createTempDirectory("pgpony-pair-recv-$tag")
        return DesktopKeyRepository(Db.open(dir.resolve("pgpony.db")), KeyMaterialStore(dir.resolve("keys")))
    }

    private fun item(kind: String, fingerprint: String?, bytes: ByteArray, name: String = "Alice") =
        PairItem(1, kind, name, fingerprint, bytes.size.toLong())

    // ── PAIRING-PROTOCOL-4 / PAIRING-IMPL-2: received items match their offer ──

    @Test
    fun aPublicKeyItemMustBeOneCertificateWithTheOfferedFingerprint() = runBlocking {
        val sender = keyring("pub-sender")
        val alice = sender.generateKey("Alice", "alice@pgpony.app", KeyAlgorithm.ED25519_CV25519, "pass")
        val bob = sender.generateKey("Bob", "bob@pgpony.app", KeyAlgorithm.ED25519_CV25519, "pass")
        val alicePub = sender.exportArmoredPublicKeyForSharing(alice.fingerprint)!!.toByteArray()
        val bobPub = sender.exportArmoredPublicKeyForSharing(bob.fingerprint)!!.toByteArray()
        val receiver = keyring("pub-receiver")
        val c = PairController(receiver, DesktopKeyEdits(receiver))

        val ok = c.check(item(PairItem.PUBLIC_KEY, alice.fingerprint.lowercase(), alicePub), alicePub)
        assertEquals(alice.fingerprint, ok.keys.single().fingerprint)
        assertTrue(ok.keys.single().userIds.single().contains("alice@pgpony.app"))
        assertFalse(ok.keys.single().hasPrivateKey)
        assertTrue(receiver.allKeys().isEmpty(), "checking writes nothing")

        // Bob's key under Alice's name and fingerprint.
        assertFailsWith<PairPrepareException> { c.check(item(PairItem.PUBLIC_KEY, alice.fingerprint, bobPub), bobPub) }
        // No fingerprint in the offer.
        assertFailsWith<PairPrepareException> { c.check(item(PairItem.PUBLIC_KEY, null, alicePub), alicePub) }
        // Two blocks in one item.
        val two = alicePub + "\n".toByteArray() + bobPub
        assertFailsWith<PairPrepareException> { c.check(item(PairItem.PUBLIC_KEY, alice.fingerprint, two), two) }
        // A secret key offered as a public key.
        val secret = sender.exportArmoredPrivateKey(alice.fingerprint)!!.toByteArray()
        assertFailsWith<PairPrepareException> { c.check(item(PairItem.PUBLIC_KEY, alice.fingerprint, secret), secret) }
        // apply runs the same checks: nothing is imported.
        assertFailsWith<PairPrepareException> { c.apply(item(PairItem.PUBLIC_KEY, alice.fingerprint, bobPub), bobPub, null) }
        assertTrue(receiver.allKeys().isEmpty())
        c.apply(item(PairItem.PUBLIC_KEY, alice.fingerprint, alicePub), alicePub, null)
        assertEquals(listOf(alice.fingerprint), receiver.allKeys().map { it.fingerprint })
    }

    @Test
    fun aKeyPairItemMustBeOneProtectedSecretKeyWithTheOfferedFingerprint() = runBlocking {
        val sender = keyring("pair-sender")
        val protectedKey = sender.generateKey("Prot", "prot@pgpony.app", KeyAlgorithm.ED25519_CV25519, "own passphrase")
        val bareKey = sender.generateKey("Bare", "bare@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val receiver = keyring("pair-receiver")
        val c = PairController(receiver, DesktopKeyEdits(receiver))

        val prot = sender.exportArmoredPrivateKey(protectedKey.fingerprint)!!.toByteArray()
        val ok = c.check(item(PairItem.KEY_PAIR, protectedKey.fingerprint, prot), prot)
        assertTrue(ok.keys.single().hasPrivateKey)

        // A secret key without a passphrase never comes in as a key pair.
        val bare = sender.exportArmoredPrivateKey(bareKey.fingerprint)!!.toByteArray()
        assertFailsWith<PairPrepareException> { c.check(item(PairItem.KEY_PAIR, bareKey.fingerprint, bare), bare) }
        // A public key offered as a key pair.
        val pub = sender.exportArmoredPublicKeyForSharing(protectedKey.fingerprint)!!.toByteArray()
        assertFailsWith<PairPrepareException> { c.check(item(PairItem.KEY_PAIR, protectedKey.fingerprint, pub), pub) }
        // The right kind of key, but not the one offered.
        assertFailsWith<PairPrepareException> { c.check(item(PairItem.KEY_PAIR, bareKey.fingerprint, prot), prot) }
        // Under the transfer passphrase the bare key passes.
        val transfer = DesktopKeyEdits(sender).transferArmor(bareKey.fingerprint, "transfer phrase")!!.toByteArray()
        c.check(item(PairItem.KEY_PAIR, bareKey.fingerprint, transfer), transfer)
        assertTrue(receiver.allKeys().isEmpty(), "checking writes nothing")
    }

    @Test
    fun aBackupItemMustBeABackupAndRestoresWithNoTrust() = runBlocking {
        val sender = keyring("backup-sender")
        val alice = sender.generateKey("Alice", "alice@pgpony.app", KeyAlgorithm.ED25519_CV25519, "pass")
        sender.updateTrustLevel(alice.fingerprint, TrustLevel.VERIFIED)
        val a = PairController(sender, DesktopKeyEdits(sender))
        val prepared = a.prepare(listOf(PairController.Outgoing.Backup), null)
        val backup = prepared.items.single()
        val bytes = prepared.payloads.getValue(backup.id)

        val receiver = keyring("backup-receiver")
        val c = PairController(receiver, DesktopKeyEdits(receiver))
        assertTrue(c.check(backup, bytes).keys.isEmpty())
        val notABackup = sender.exportArmoredPublicKeyForSharing(alice.fingerprint)!!.toByteArray()
        assertFailsWith<PairPrepareException> { c.check(item(PairItem.BACKUP, null, notABackup), notABackup) }

        c.apply(backup, bytes, prepared.recoveryCode)
        val restored = receiver.byFingerprint(alice.fingerprint)
        assertNotNull(restored)
        assertEquals(TrustLevel.UNKNOWN, restored.trustLevel, "trust never comes from the other device")
    }

    // ── PAIRING-PROTOCOL-2 / PAIRING-IMPL-4: nothing pasted escapes ──

    @Test
    fun aMalformedInviteIsUnreadableNotACrash() {
        val h = "A".repeat(22)
        for (inner in listOf(":::1", "1:2", ".:1", "..:", "1::2::3", "1.2.3.4:5", "....::")) {
            assertNull(PairController.target("pgpony-pair:1?a=[$inner]:5&h=$h"), inner)
        }
        val ok = PairController.target("pgpony-pair:1?a=[::ffff:127.0.0.1]:5&h=$h")
        assertNotNull(ok)
        assertEquals("127.0.0.1", ok.addresses.single().address.hostAddress)
    }

    // ── PAIRING-PROTOCOL-1: join errors that may mean the window was taken ──

    @Test
    fun aRefusedOrCutJoinSaysTheWindowMayBeTaken() {
        assertTrue(PairController.windowMayBeTaken(ConnectException("Connection refused")))
        assertTrue(PairController.windowMayBeTaken(java.net.SocketException("Connection reset")))
        assertTrue(PairController.windowMayBeTaken(PairException(PairFailure.CLOSED, "the other side closed the connection")))
        assertFalse(PairController.windowMayBeTaken(SocketTimeoutException("connect timed out")))
        assertFalse(PairController.windowMayBeTaken(java.net.NoRouteToHostException("no route")))
        assertFalse(PairController.windowMayBeTaken(PairException(PairFailure.HANDSHAKE, "bad key")))
        // A refused connection to a closed port.
        val port = java.net.ServerSocket(0).use { it.localPort }
        val controller = PairController(keyring("join"), DesktopKeyEdits(keyring("join-edits")))
        val e = assertFailsWith<Exception> {
            controller.join(PairController.JoinTarget(listOf(java.net.InetSocketAddress(InetAddress.getLoopbackAddress(), port)), null))
        }
        assertTrue(PairController.windowMayBeTaken(e), e.toString())
        assertEquals(tr("d_pair_fail_window_taken"), joinFailureMessage(e))
    }

    // ── PAIRING-PROTOCOL-5 / PAIRING-IMPL-3: the host window ──

    @Test
    fun theHostNamesThePeerAsSoonAsItConnectsAndCloseEndsTheHandshake() {
        val window = PairController.HostWindow()
        val peer = CompletableFuture.supplyAsync({ window.awaitConnection() }, threads)
        Socket(InetAddress.getLoopbackAddress(), window.port).use { s ->
            assertEquals("127.0.0.1", peer.get(10, TimeUnit.SECONDS))
            // The connection says nothing; closing the window ends the handshake at once.
            val handshake = CompletableFuture.supplyAsync({ runCatching { window.handshake() } }, threads)
            Thread.sleep(200)
            assertFalse(handshake.isDone)
            window.close()
            assertTrue(handshake.get(5, TimeUnit.SECONDS).isFailure)
        }
        // The listener is gone once a connection was taken.
        assertFailsWith<java.io.IOException> { Socket(InetAddress.getLoopbackAddress(), window.port).close() }
    }

    @Test
    fun theHostSubnetsAreReadWithoutFailing() {
        // Whatever the machine has, this never throws, and every subnet fits its address.
        PairController.hostSubnets().forEach { assertTrue(it.prefixLength in 0..it.address.size * 8) }
    }
}
