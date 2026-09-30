// PairControllerTest.kt
// PGPony Desktop 3.0.0, F1: two keyrings pair over loopback and move a protected key pair, an
// unprotected key pair (which must travel under the transfer passphrase), a public key and a
// full backup, each imported through the ordinary import and restore code.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.pair.PairAnswer
import com.pgpony.android.pair.PairItem
import com.pgpony.android.pair.PairMessage
import com.pgpony.android.pair.PairOffer
import com.pgpony.android.pair.PairSession
import kotlinx.coroutines.runBlocking
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.file.Files
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PairControllerTest {

    private val threads = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }

    private fun keyring(tag: String): DesktopKeyRepository {
        val dir = Files.createTempDirectory("pgpony-pair-$tag")
        return DesktopKeyRepository(Db.open(dir.resolve("pgpony.db")), KeyMaterialStore(dir.resolve("keys")))
    }

    private fun sessions(a: PairController, b: PairController): Pair<PairSession, PairSession> {
        val window = PairController.HostWindow()
        val host = CompletableFuture.supplyAsync({ window.accept() }, threads)
        val joiner = b.join(InetSocketAddress(InetAddress.getLoopbackAddress(), window.port))
        val h = host.get(10, TimeUnit.SECONDS)
        assertEquals(h.code, joiner.code)
        val hs = CompletableFuture.supplyAsync({ h.confirm() }, threads)
        val js = joiner.confirm()
        return hs.get(10, TimeUnit.SECONDS) to js
    }

    @Test
    fun keysAndABackupMoveBetweenTwoKeyrings() = runBlocking {
        val repoA = keyring("a")
        val repoB = keyring("b")
        val editsA = DesktopKeyEdits(repoA)
        val editsB = DesktopKeyEdits(repoB)
        val protectedKey = repoA.generateKey("Protected", "protected@pgpony.app", KeyAlgorithm.ED25519_CV25519, "own passphrase")
        val bareKey = repoA.generateKey("Bare", "bare@pgpony.app", KeyAlgorithm.V6_ED25519, null)
        val a = PairController(repoA, editsA)
        val b = PairController(repoB, editsB)

        val candidates = a.candidates()
        val pairs = candidates.filterIsInstance<PairController.Outgoing.KeyPair>()
        assertEquals(2, pairs.size)
        assertTrue(pairs.single { it.fingerprint == protectedKey.fingerprint }.protected)
        assertTrue(!pairs.single { it.fingerprint == bareKey.fingerprint }.protected)

        // A key pair without a passphrase never leaves unprotected.
        assertFailsWith<PairPrepareException> { a.prepare(pairs, null) }
        val prepared = a.prepare(pairs + PairController.Outgoing.Backup, "transfer phrase")
        assertNotNull(prepared.recoveryCode)
        assertEquals(listOf(PairItem.KEY_PAIR, PairItem.KEY_PAIR, PairItem.BACKUP), prepared.items.map { it.kind })
        // The stored bare key is untouched by the export.
        assertTrue(!editsA.isPassphraseProtected(bareKey.fingerprint))

        val (sa, sb) = sessions(a, b)
        sa.sendOffer(PairOffer(prepared.items))
        val offer = (sb.receive() as PairMessage.Offer).offer
        val keyPairs = offer.items.filter { it.kind == PairItem.KEY_PAIR }
        sb.sendAnswer(PairAnswer(keyPairs.map { it.id }))
        val answer = (sa.receive() as PairMessage.Answer).answer
        val sent = CompletableFuture.runAsync({
            answer.accept.forEach { sa.sendItem(it, prepared.payloads.getValue(it)) }
        }, threads)
        val expected = keyPairs.associate { it.id to it.size }
        repeat(keyPairs.size) {
            val item = sb.receive(expected) as PairMessage.Item
            b.apply(offer.items.single { it.id == item.id }, item.bytes, null)
        }
        sent.get(10, TimeUnit.SECONDS)

        val imported = repoB.allKeys().associateBy { it.fingerprint }
        assertTrue(imported.getValue(protectedKey.fingerprint).isKeyPair)
        assertTrue(imported.getValue(bareKey.fingerprint).isKeyPair)
        assertTrue(editsB.isPassphraseProtected(bareKey.fingerprint), "the bare key arrives under the transfer passphrase")
        // The transfer passphrase opens it, and can be removed on the receiving side.
        editsB.changePassphrase(bareKey.fingerprint, "transfer phrase", "")
        assertTrue(!editsB.isPassphraseProtected(bareKey.fingerprint))

        // The backup restores on a third keyring with the code the sending screen showed.
        val repoC = keyring("c")
        val c = PairController(repoC, DesktopKeyEdits(repoC))
        val backupItem = prepared.items.single { it.kind == PairItem.BACKUP }
        assertFailsWith<PairPrepareException> { c.apply(backupItem, prepared.payloads.getValue(backupItem.id), null) }
        c.apply(backupItem, prepared.payloads.getValue(backupItem.id), prepared.recoveryCode)
        assertEquals(setOf(protectedKey.fingerprint, bareKey.fingerprint), repoC.allKeys().map { it.fingerprint }.toSet())

        sa.sendBye()
        assertEquals(PairMessage.Bye, sb.receive())
        sa.close()
    }

    @Test
    fun addressesParseAsTheHostScreenShowsThem() {
        assertEquals(49152, PairController.parse("192.168.1.20:49152")!!.port)
        assertEquals(InetAddress.getByName("192.168.1.20"), PairController.parse(" 192.168.1.20:49152 ")!!.address)
        assertEquals(8080, PairController.parse("[fd00::1]:8080")!!.port)
        assertNull(PairController.parse("192.168.1.20"))
        assertNull(PairController.parse("192.168.1.20:0"))
        assertNull(PairController.parse("192.168.1.20:70000"))
        assertNull(PairController.parse("fd00::1:8080"))
        assertEquals(InetAddress.getByName("fd00::1"), PairController.parse(PairController.display(InetAddress.getByName("fd00::1"), 8080))!!.address)
        assertEquals("10.0.0.2:1", PairController.display(InetAddress.getByName("10.0.0.2"), 1))
    }

    @Test
    fun aHostWindowClosesItsListenerOnceSomeoneConnects() {
        val window = PairController.HostWindow()
        val port = window.port
        val host = CompletableFuture.supplyAsync({ runCatching { window.accept() } }, threads)
        java.net.Socket(InetAddress.getLoopbackAddress(), port).use { it.getOutputStream().write("nope".toByteArray()) }
        assertTrue(host.get(10, TimeUnit.SECONDS).isFailure)
        assertFailsWith<java.io.IOException> { java.net.Socket(InetAddress.getLoopbackAddress(), port).close() }
        window.close()
    }

    @Test
    fun aPastedInviteChecksTheHostKey() {
        // What the host screen would copy, pointed at loopback: the join takes the key check.
        for (right in listOf(true, false)) {
            val window = PairController.HostWindow()
            val key = if (right) window.hostKey.public else com.pgpony.android.pair.PairCrypto.keyPair().public
            val invite = com.pgpony.android.pair.PairInvite.forHostKey(
                key, listOf(com.pgpony.android.pair.PairInvite.Address("127.0.0.1", window.port))
            )
            val target = PairController.target(invite.toUri())
            assertNotNull(target)
            assertContentEquals(invite.hostKeyHash, target.hostKeyHash)
            val host = CompletableFuture.supplyAsync({ runCatching { window.accept() } }, threads)
            val controller = PairController(keyring("invite"), DesktopKeyEdits(keyring("invite-edits")))
            if (right) {
                val joiner = controller.join(target)
                assertEquals(host.get(10, TimeUnit.SECONDS).getOrThrow().code, joiner.code)
                joiner.reject()
            } else {
                val e = assertFailsWith<com.pgpony.android.pair.PairException> { controller.join(target) }
                assertEquals(com.pgpony.android.pair.PairFailure.HANDSHAKE, e.failure)
                assertTrue(host.get(10, TimeUnit.SECONDS).isFailure)
            }
            window.close()
        }
        // A typed address still works; something that starts like an invite but is not one does not.
        assertNull(PairController.target("192.168.1.20:49152")!!.hostKeyHash)
        assertNull(PairController.target("pgpony-pair:1?a=192.168.1.20:49152"))
        assertTrue(PairController.looksLikeInvite(" PGPONY-PAIR:2?x"))
    }
}
