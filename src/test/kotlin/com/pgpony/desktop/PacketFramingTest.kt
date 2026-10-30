// PacketFramingTest.kt
// PGPony Desktop 3.0.4: key blocks at rest use current-format packet headers (PacketFraming in
// KeyMaterialStore.kt). A user found the stored copy of a key and its export differing in their
// Base64 although every packet was the same: BouncyCastle had written legacy headers for the
// packets it built, while the export used the current format.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import kotlinx.coroutines.runBlocking
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.security.SecureRandom
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class PacketFramingTest {

    /** (current format?, tag, body) for every packet of [raw]. */
    private fun packets(raw: ByteArray): List<Triple<Boolean, Int, ByteArray>> {
        val out = ArrayList<Triple<Boolean, Int, ByteArray>>()
        var p = 0
        while (p < raw.size) {
            val c = raw[p].toInt() and 0xFF
            p++
            val current = c and 0x40 != 0
            val tag: Int
            val len: Int
            if (current) {
                tag = c and 0x3F
                val l0 = raw[p].toInt() and 0xFF
                when {
                    l0 < 192 -> { len = l0; p += 1 }
                    l0 < 224 -> { len = ((l0 - 192) shl 8) + (raw[p + 1].toInt() and 0xFF) + 192; p += 2 }
                    else -> { len = java.nio.ByteBuffer.wrap(raw, p + 1, 4).int; p += 5 }
                }
            } else {
                tag = (c shr 2) and 0x0F
                when (c and 3) {
                    0 -> { len = raw[p].toInt() and 0xFF; p += 1 }
                    1 -> { len = ((raw[p].toInt() and 0xFF) shl 8) or (raw[p + 1].toInt() and 0xFF); p += 2 }
                    else -> { len = java.nio.ByteBuffer.wrap(raw, p, 4).int; p += 4 }
                }
            }
            out += Triple(current, tag, raw.copyOfRange(p, p + len))
            p += len
        }
        return out
    }

    /** A v4 Ed25519 key with a User ID, written by BouncyCastle the way the stores used to keep it. */
    private fun bcRing(): PGPPublicKeyRing {
        val g = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()
        g.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
        val pair = BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, g.generateKeyPair(), Date())
        val sha1 = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, pair, "Framing <framing@example.invalid>", sha1, null, null,
            BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.EDDSA_LEGACY, HashAlgorithmTags.SHA256), null
        )
        return gen.generatePublicKeyRing()
    }

    private fun armor(raw: ByteArray, comment: String? = null): String {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).apply {
            clearHeaders()
            comment?.let { addHeader("Comment", it) }
            write(raw)
            close()
        }
        return out.toString(Charsets.UTF_8)
    }

    /** The same ring with every header in the legacy format, as an older store could hold it. */
    private fun legacy(raw: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        for ((_, tag, body) in packets(raw)) {
            assertTrue(tag < 16)
            out.write(0x80 or (tag shl 2) or 2)
            out.write(java.nio.ByteBuffer.allocate(4).putInt(body.size).array())
            out.write(body)
        }
        return out.toByteArray()
    }

    @Test
    fun legacyHeadersBecomeCurrentAndBodiesStayTheSame() {
        val ring = bcRing()
        val raw = legacy(ring.encoded)
        val armored = armor(raw, "kept")
        val current = PacketFraming.currentArmor(armored)
        assertNotEquals(armored, current)
        assertTrue(current.contains("Comment: kept"), "armor headers are kept")
        val after = CompositeSigPacket.dearmor(current)
        val before = packets(raw)
        val now = packets(after)
        assertEquals(before.size, now.size)
        assertTrue(now.all { it.first }, "every header in the current format")
        for (i in before.indices) {
            assertEquals(before[i].second, now[i].second)
            assertContentEquals(before[i].third, now[i].third, "packet $i body unchanged")
        }
        val reread = PGPPublicKeyRing(after, BcKeyFingerprintCalculator())
        assertContentEquals(ring.publicKey.fingerprint, reread.publicKey.fingerprint)
        assertEquals(current, PacketFraming.currentArmor(current), "idempotent")
    }

    @Test
    fun anythingElseComesBackUnchanged() {
        val raw = legacy(bcRing().encoded)
        val armored = armor(raw)
        val badCrc = armored.lines().joinToString("\n") { if (it.startsWith("=")) "=AAAA" else it }
        assertEquals(badCrc, PacketFraming.currentArmor(badCrc), "a bad checksum is left alone")
        val two = armored + armored
        assertEquals(two, PacketFraming.currentArmor(two), "two blocks are left alone")
        val message = armored.replace("PGP PUBLIC KEY BLOCK", "PGP MESSAGE")
        assertEquals(message, PacketFraming.currentArmor(message), "only key blocks are reframed")
        assertEquals("not armor", PacketFraming.currentArmor("not armor"))
        val current = PacketFraming.currentArmor(armored)
        assertEquals(current, PacketFraming.currentArmor(current), "a current block is returned as it is")
    }

    @Test
    fun longPacketsKeepTheirLength() {
        val body = ByteArray(9000) { it.toByte() }
        val raw = ByteArrayOutputStream().apply {
            write(0x80 or (13 shl 2) or 2)
            write(java.nio.ByteBuffer.allocate(4).putInt(body.size).array())
            write(body)
            write(0x80 or (13 shl 2) or 1)
            write(byteArrayOf(0x01, 0x00))
            write(ByteArray(256))
        }.toByteArray()
        val current = PacketFraming.currentFormat(raw)!!
        val p = packets(current)
        assertEquals(2, p.size)
        assertContentEquals(body, p[0].third)
        assertEquals(256, p[1].third.size)
        assertTrue(p.all { it.first })
    }

    @Test
    fun theStoreWritesCurrentHeadersAndRewritesAnOldFileOnce() {
        val dir = Files.createTempDirectory("pgpony-framing-test")
        val store = KeyMaterialStore(dir)
        val ring = bcRing()
        val fp = ring.publicKey.fingerprint.joinToString("") { "%02x".format(it) }
        val legacyArmor = armor(legacy(ring.encoded))

        store.storePublic(fp, legacyArmor)
        val file = dir.resolve("$fp.pub.asc")
        assertTrue(packets(CompositeSigPacket.dearmor(Files.readString(file))).all { it.first }, "stored current")

        Files.writeString(file, legacyArmor)
        val loaded = store.loadPublic(fp)!!
        assertTrue(packets(CompositeSigPacket.dearmor(loaded)).all { it.first }, "loaded current")
        assertEquals(loaded, Files.readString(file), "the old file was rewritten")
    }

    @Test
    fun aGeneratedPostQuantumKeyIsStoredInTheCurrentFormat() = runBlocking {
        val dir = Files.createTempDirectory("pgpony-framing-gen")
        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        val entity = repo.generateKey(
            name = "Framing PQC", email = "framing@example.invalid",
            algorithm = KeyAlgorithm.MLKEM1024_X448_V6, passphrase = "test-passphrase"
        )
        val file = dir.resolve("keys").resolve("${entity.fingerprint.lowercase()}.pub.asc")
        val onDisk = packets(CompositeSigPacket.dearmor(Files.readString(file)))
        assertTrue(onDisk.all { it.first }, "every stored header in the current format")
        assertTrue(onDisk.any { it.second == 14 && it.third[0].toInt() == 6 && it.third[5].toInt() == 36 }, "the ML-KEM-1024+X448 subkey is there")
        db.close()
    }
}
