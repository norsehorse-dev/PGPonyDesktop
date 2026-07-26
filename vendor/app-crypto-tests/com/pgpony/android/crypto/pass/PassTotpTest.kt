// PassTotpTest.kt
// PGPony — RFC 6238 conformance + URI-parsing contract for the shared TOTP core.
//
// The vector block is Appendix B of RFC 6238 verbatim: the ASCII seeds "12345678901234567890"
// (SHA1, 20 bytes), the same digits repeated to 32 bytes (SHA256) and 64 bytes (SHA512), each
// base32-encoded here the way an authenticator would write it into an `otpauth://` URI. If a
// change to PassTotp breaks any of these, every code PGPony shows is wrong.
//
// This file is vendored into PGPonyDesktop's test source set (vendor/app-crypto-tests), so the
// same assertions run on both apps.

package com.pgpony.android.crypto.pass

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PassTotpTest {

    // The RFC 6238 seeds, base32-encoded (SHA256's encoding carries "====" padding — the
    // decoder has to tolerate it, as real authenticators emit it).
    private val sha1Seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    private val sha256Seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
    private val sha512Seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" +
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="

    private val times = listOf(59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L)

    private fun uri(secret: String, algorithm: String, digits: Int = 8, period: Int = 30) =
        "otpauth://totp/RFC6238:vector?secret=$secret&algorithm=$algorithm" +
            "&digits=$digits&period=$period&issuer=RFC6238"

    private fun codes(secret: String, algorithm: String): List<String> {
        val config = PassTotp.parse(uri(secret, algorithm))
        assertNotNull("URI should parse: $algorithm", config)
        return times.map { PassTotp.code(config!!, it)!! }
    }

    @Test
    fun rfc6238Sha1VectorsMatch() {
        assertEquals(
            listOf("94287082", "07081804", "14050471", "89005924", "69279037", "65353130"),
            codes(sha1Seed, "SHA1")
        )
    }

    @Test
    fun rfc6238Sha256VectorsMatch() {
        assertEquals(
            listOf("46119246", "68084774", "67062674", "91819424", "90698825", "77737706"),
            codes(sha256Seed, "SHA256")
        )
    }

    @Test
    fun rfc6238Sha512VectorsMatch() {
        assertEquals(
            listOf("90693936", "25091201", "99943326", "93441116", "38618901", "47863826"),
            codes(sha512Seed, "SHA512")
        )
    }

    @Test
    fun defaultsAreSha1SixDigitsThirtySeconds() {
        val config = PassTotp.parse("otpauth://totp/Example:alice?secret=$sha1Seed")!!
        assertEquals("SHA1", config.algorithm)
        assertEquals(6, config.digits)
        assertEquals(30, config.periodSeconds)
        // Same vector as the 8-digit SHA1 case, truncated to six digits: 94287082 → 287082.
        assertEquals("287082", PassTotp.code(config, 59L))
    }

    @Test
    fun theCodeIsStableWithinAStepAndRollsAtTheBoundary() {
        val config = PassTotp.parse("otpauth://totp/Example:alice?secret=$sha1Seed")!!
        val atStart = PassTotp.code(config, 1234567890L / 30 * 30)
        val atEnd = PassTotp.code(config, 1234567890L / 30 * 30 + 29)
        val next = PassTotp.code(config, 1234567890L / 30 * 30 + 30)
        assertEquals(atStart, atEnd)
        assertTrue("a new step must produce a different code", atStart != next)
    }

    @Test
    fun secondsRemainingCountsDownWithinTheStep() {
        val config = PassTotp.parse("otpauth://totp/Example:alice?secret=$sha1Seed")!!
        assertEquals(30, PassTotp.secondsRemaining(config, 0L))
        assertEquals(29, PassTotp.secondsRemaining(config, 1L))
        assertEquals(1, PassTotp.secondsRemaining(config, 29L))
        assertEquals(30, PassTotp.secondsRemaining(config, 30L))
    }

    @Test
    fun aCustomPeriodIsHonored() {
        val config = PassTotp.parse("otpauth://totp/Example:alice?secret=$sha1Seed&period=60")!!
        assertEquals(60, config.periodSeconds)
        assertEquals(60, PassTotp.secondsRemaining(config, 0L))
        // period 60 at t=59 is step 0, the same step as t=0 — unlike the 30-second default.
        assertEquals(PassTotp.code(config, 0L), PassTotp.code(config, 59L))
    }

    @Test
    fun base32IsCaseInsensitiveAndIgnoresPrintingSeparators() {
        val plain = PassTotp.decodeBase32(sha1Seed)!!
        val messy = PassTotp.decodeBase32("gezd gnbv-gy3t qojq gezd gnbv-gy3t qojq")!!
        assertEquals(String(plain, Charsets.US_ASCII), String(messy, Charsets.US_ASCII))
        assertEquals("12345678901234567890", String(plain, Charsets.US_ASCII))
    }

    @Test
    fun base32RejectsInvalidCharactersAndTruncatedGroups() {
        assertNull(PassTotp.decodeBase32("MFRGG!!!"))     // '!' isn't in the alphabet
        assertNull(PassTotp.decodeBase32("MFRGG1"))       // '1' isn't either (0/1/8/9 excluded)
        assertNull(PassTotp.decodeBase32("A"))            // 5 bits — no whole byte
    }

    @Test
    fun theLabelSuppliesIssuerAndAccountAndTheQueryParameterWins() {
        val fromLabel = PassTotp.parse("otpauth://totp/GitHub:alice%40example.com?secret=$sha1Seed")!!
        assertEquals("GitHub", fromLabel.issuer)
        assertEquals("alice@example.com", fromLabel.account)
        assertEquals("GitHub (alice@example.com)", fromLabel.label)

        val paramWins = PassTotp.parse(
            "otpauth://totp/Old:alice?secret=$sha1Seed&issuer=New%20Provider"
        )!!
        assertEquals("New Provider", paramWins.issuer)
        assertEquals("alice", paramWins.account)

        val bare = PassTotp.parse("otpauth://totp/alice?secret=$sha1Seed")!!
        assertNull(bare.issuer)
        assertEquals("alice", bare.account)
    }

    @Test
    fun hotpAndOtherSchemesAreRefusedRatherThanGuessed() {
        assertNull(PassTotp.parse("otpauth://hotp/Example:alice?secret=$sha1Seed&counter=1"))
        assertNull(PassTotp.parse("https://example.com/?secret=$sha1Seed"))
        assertNull(PassTotp.parse(""))
        assertNull(PassTotp.parse("otpauth://totp/Example:alice"))                  // no secret
        assertNull(PassTotp.parse("otpauth://totp/Example:alice?secret="))          // empty secret
        assertNull(PassTotp.parse("otpauth://totp/Example:alice?secret=NOT!BASE32"))
    }

    @Test
    fun outOfRangeParametersAreRefused() {
        assertNull(PassTotp.parse("otpauth://totp/a?secret=$sha1Seed&algorithm=MD5"))
        assertNull(PassTotp.parse("otpauth://totp/a?secret=$sha1Seed&digits=5"))
        assertNull(PassTotp.parse("otpauth://totp/a?secret=$sha1Seed&digits=9"))
        assertNull(PassTotp.parse("otpauth://totp/a?secret=$sha1Seed&digits=six"))
        assertNull(PassTotp.parse("otpauth://totp/a?secret=$sha1Seed&period=0"))
        assertNull(PassTotp.parse("otpauth://totp/a?secret=$sha1Seed&period=-30"))
    }

    @Test
    fun theSchemeAndAlgorithmNamesAreCaseInsensitive() {
        val config = PassTotp.parse("OTPAUTH://TOTP/Example:alice?secret=$sha1Seed&algorithm=sha256")
        assertNotNull(config)
        assertEquals("SHA256", config!!.algorithm)
    }

    @Test
    fun aUriFromTheEntryParserRoundTripsIntoACode() {
        // The realistic path: a `pass` entry whose second line is the otpauth URI.
        val entry = PassEntryParser.parse(
            "hunter2\nusername: alice\notpauth://totp/GitHub:alice?secret=$sha1Seed\n"
        )
        val config = PassTotp.parse(entry.otpauth!!)!!
        assertEquals("287082", PassTotp.code(config, 59L))
        assertEquals("287 082", PassTotp.grouped(PassTotp.code(config, 59L)!!))
    }

    @Test
    fun groupingSplitsInTheMiddleAndLeavesShortCodesAlone() {
        assertEquals("123 456", PassTotp.grouped("123456"))
        assertEquals("1234 5678", PassTotp.grouped("12345678"))
        assertEquals("123 4567", PassTotp.grouped("1234567"))
        assertEquals("1234", PassTotp.grouped("1234"))
    }

    @Test
    fun theConfigToStringNeverPrintsTheSecret() {
        val config = PassTotp.parse("otpauth://totp/GitHub:alice?secret=$sha1Seed")!!
        val text = config.toString()
        assertTrue(text.contains("GitHub"))
        assertTrue("toString must not leak key material", !text.contains(sha1Seed))
    }
}
