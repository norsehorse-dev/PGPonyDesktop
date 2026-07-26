// CliTest.kt
// D10 validation — the CLI's pure pieces: the option parser and the key-selector resolver
// (fingerprint / key id / email / name). The verbs themselves are thin wrappers over the
// engine + repository, which are covered by their own suites; the parsing and matching are the
// new logic worth pinning.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.PGPKeyEntity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CliTest {

    // ── Option parser ───────────────────────────────────────────────────

    @Test
    fun parsesFlagsValuesRepeatsAndPositional() {
        val o = Options(listOf("-a", "-r", "alice@x", "--recipient", "bob@y", "-o", "out.asc", "message.txt"))
        assertTrue(o.flag("--armor", "-a"))
        assertTrue(!o.flag("--symmetric", "-c"))
        assertEquals(listOf("alice@x", "bob@y"), o.all("--recipient", "-r"))
        assertEquals("out.asc", o.value("--output", "-o"))
        assertEquals("message.txt", o.positional())
    }

    // D10 (Fix1) — repeats follow the COMMAND LINE, not the order of the alias names we happen
    // to pass to all()/value(). Grouping by option name put every long-form value ahead of every
    // short-form one, silently reordering recipients.
    @Test
    fun repeatedOptionsKeepCommandLineOrderAcrossAliases() {
        val o = Options(listOf("--recipient", "carol@x", "-r", "alice@x", "--recipient=bob@y", "-r", "dave@z"))
        assertEquals(listOf("carol@x", "alice@x", "bob@y", "dave@z"), o.all("--recipient", "-r"))
        assertEquals(listOf("carol@x", "alice@x", "bob@y", "dave@z"), o.all("-r", "--recipient"))
        assertEquals("carol@x", o.value("--recipient", "-r"), "value() is the first occurrence")
    }

    @Test
    fun shortFormValueIsFoundWhenLongFormAbsent() {
        val o = Options(listOf("-o", "out.asc", "-u", "me@x"))
        assertEquals("out.asc", o.value("--output", "-o"))
        assertEquals("me@x", o.value("--sign-as", "-u"))
    }

    @Test
    fun parsesEqualsForm() {
        val o = Options(listOf("--output=out.gpg", "--algo=rsa4096"))
        assertEquals("out.gpg", o.value("--output", "-o"))
        assertEquals("rsa4096", o.value("--algo"))
    }

    @Test
    fun doubleDashEndsOptions() {
        val o = Options(listOf("-a", "--", "-weird-filename.txt"))
        assertTrue(o.flag("-a"))
        assertEquals("-weird-filename.txt", o.positional(), "after -- everything is positional")
    }

    // ── Key resolver ────────────────────────────────────────────────────

    private fun key(fp: String, email: String, name: String, keyPair: Boolean = true) = PGPKeyEntity(
        id = fp, fingerprint = fp, userID = "$name <$email>", userName = name, userEmail = email,
        algorithm = KeyAlgorithm.ED25519_CV25519, isKeyPair = keyPair, createdAt = 0L
    )

    private val keys = listOf(
        key("AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555", "alice@example.com", "Alice"),
        key("FFFF9999EEEE8888DDDD7777CCCC6666BBBB5555", "bob@example.com", "Bob", keyPair = false)
    )

    @Test
    fun matchesByEmailExact() {
        val m = Cli.matchKeys(keys, "alice@example.com")
        assertEquals(1, m.size); assertEquals("Alice", m.first().userName)
    }

    @Test
    fun matchesByFingerprintSuffix() {
        val m = Cli.matchKeys(keys, "EEEE5555")   // tail of Alice's fingerprint
        assertEquals(1, m.size); assertEquals("Alice", m.first().userName)
    }

    @Test
    fun matchesByNameSubstringCaseInsensitive() {
        assertEquals(1, Cli.matchKeys(keys, "bob").size)
        assertEquals("Bob", Cli.matchKeys(keys, "BO").first().userName)
    }

    @Test
    fun noMatchIsEmpty() {
        assertTrue(Cli.matchKeys(keys, "nobody@nowhere.test").isEmpty())
    }

    // ── Algorithm names ─────────────────────────────────────────────────

    @Test
    fun algorithmAliases() {
        assertEquals(KeyAlgorithm.ED25519_CV25519, Cli.parseAlgorithm("ed25519"))
        assertEquals(KeyAlgorithm.ED25519_CV25519, Cli.parseAlgorithm("default"))
        assertEquals(KeyAlgorithm.RSA_4096, Cli.parseAlgorithm("rsa4096"))
        assertEquals(KeyAlgorithm.RSA_4096, Cli.parseAlgorithm("rsa-4096"))
        assertEquals(KeyAlgorithm.MLKEM768_X25519_V6, Cli.parseAlgorithm("mlkem-v6"))
        assertEquals(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, Cli.parseAlgorithm("mlkem-librepgp"))
    }

    @Test
    fun unknownAlgorithmThrows() {
        assertFailsWith<Exception> { Cli.parseAlgorithm("blowfish") }
    }
}
