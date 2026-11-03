// GitHubKeyFetcher.kt
// PGPony Android, 4.7.0 (item 42, #81): look up the OpenPGP keys a GitHub
// user has added to their account, so the signer of a commit can be imported.
//
// GitHub serves them at https://github.com/<user>.gpg. The request goes
// through the shared proxy-aware client (HttpClientFactory), so the offline
// switch, Tor through Orbot and a custom proxy apply exactly as they do to a
// key server or WKD lookup, with the same timeouts. The body is read with a
// 2 MB ceiling; a larger answer is refused, never truncated.
//
// GitHub answers in one of three shapes, all handled in [classify]:
//   * 200 with one or more PUBLIC KEY BLOCKs, one block per key. The body is
//     validated like a key server answer (KeyResponse), so what comes back is
//     one public key block holding every certificate, and the import preview
//     lists them all (4.6.0 item 17.9).
//   * 200 for a user with no keys: an armored block whose only content is a
//     "Note: This user hasn't uploaded any GPG keys." header and an empty
//     payload. A plain text body saying the same is treated alike.
//   * 404 for a username that does not exist.
//
// The HTTP request sits behind [Transport] so the classification can be
// tested without a network. Nothing is stored here: the caller shows the
// keys for a fingerprint check and imports only on confirm.

package com.pgpony.android.network

import io.ktor.client.request.get
import io.ktor.client.request.header
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.bcpg.ArmoredInputStream

object GitHubKeyFetcher {

    /** GitHub's own limit on username length. */
    const val MAX_USERNAME_LENGTH = 39
    /** Largest answer accepted. A user with many large RSA keys stays far below it. */
    const val MAX_RESPONSE_BYTES = 2L * 1024 * 1024

    // Letters and digits, with single hyphens between them: no leading,
    // trailing or doubled hyphen.
    private val USERNAME = Regex("[A-Za-z0-9]+(-[A-Za-z0-9]+)*")

    private val PUBLIC_BLOCK = Regex(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----[\\s\\S]*?-----END PGP PUBLIC KEY BLOCK-----"
    )

    /** One HTTP answer: status, Content-Type and the (capped) body. */
    class Answer(val status: Int, val contentType: String?, val body: ByteArray)

    /** The request itself. Throws on a network failure. */
    fun interface Transport {
        suspend fun get(url: String): Answer
    }

    sealed class Result {
        /** Validated public key armor (every key the user has) and where it came from. */
        data class Keys(val armored: String, val username: String, val url: String) : Result()
        /** The user exists and has added no OpenPGP keys to GitHub. */
        data class NoKeys(val username: String) : Result()
        /** GitHub has no user by this name (404). */
        data class NotFound(val username: String) : Result()
        /** The answer held key armor, but nothing this app can read as a public key. */
        data class Unreadable(val username: String) : Result()
        object InvalidUsername : Result()
        object Offline : Result()
        data class HttpError(val status: Int) : Result()
        data class Failed(val message: String) : Result()
    }

    /** True when [name] is a valid GitHub username as typed (no "@", no URL). */
    fun isValidUsername(name: String): Boolean =
        name.length in 1..MAX_USERNAME_LENGTH && USERNAME.matches(name)

    /**
     * The GitHub username in [input], or null when it is not one. Accepts a
     * bare name, "@name", and a pasted profile or key link: "github.com/name",
     * "https://github.com/name", "https://www.github.com/name/" and the same
     * with ".gpg" on the end. A link to anything below the profile (a
     * repository, say) is refused rather than guessed at.
     */
    fun normalizeUsername(input: String): String? {
        var s = input.trim()
        val lower = s.lowercase()
        val prefix = listOf(
            "https://www.github.com/", "http://www.github.com/", "https://github.com/",
            "http://github.com/", "www.github.com/", "github.com/"
        ).firstOrNull { lower.startsWith(it) }
        if (prefix != null) {
            s = s.substring(prefix.length).substringBefore('?').substringBefore('#').trimEnd('/')
        } else {
            s = s.removePrefix("@")
        }
        if (s.endsWith(".gpg", ignoreCase = true)) s = s.dropLast(4)
        return s.takeIf { isValidUsername(it) }
    }

    /** The key link for a valid [username]. */
    fun keysUrl(username: String): String = "https://github.com/$username.gpg"

    /** What a GitHub [answer] for [username] means (see the header). */
    fun classify(username: String, answer: Answer): Result {
        if (answer.status == 404) return Result.NotFound(username)
        if (answer.status !in 200..299) return Result.HttpError(answer.status)
        if (KeyResponse.isHtml(answer.contentType)) return Result.Unreadable(username)
        val body = answer.body
        if (body.isEmpty()) return Result.NoKeys(username)
        val armored: String? = KeyResponse.validate(body, answer.contentType)
        if (armored != null) return Result.Keys(armored, username, keysUrl(username))
        // Binary data that did not validate as keys above: not a note either.
        // (validate accepts binary key data, so this check comes after it.)
        if ((body[0].toInt() and 0x80) != 0) return Result.Unreadable(username)
        val text = String(body, Charsets.UTF_8)
        val blocks = PUBLIC_BLOCK.findAll(text).map { it.value }.toList()
        if (blocks.isEmpty()) {
            // No armor at all: a plain note that the user has no keys.
            return if (text.contains("uploaded any GPG keys", ignoreCase = true) || text.isBlank())
                Result.NoKeys(username) else Result.Unreadable(username)
        }
        return if (blocks.all { isEmptyBlock(it) }) Result.NoKeys(username) else Result.Unreadable(username)
    }

    // True when an armored block decodes cleanly to no bytes at all, the shape
    // GitHub uses for "no keys".
    private fun isEmptyBlock(block: String): Boolean = runCatching {
        ArmoredInputStream(block.byteInputStream(Charsets.UTF_8)).use { it.readBytes() }.isEmpty()
    }.getOrDefault(false)

    /**
     * Look up [input] (a username or a pasted link, see [normalizeUsername]).
     * [offline] and [transport] are parameters only so tests can replace them.
     */
    suspend fun fetch(
        input: String,
        transport: Transport = NetworkTransport,
        offline: () -> Boolean = { OfflineMode.isEnabled() }
    ): Result {
        val username = normalizeUsername(input) ?: return Result.InvalidUsername
        if (offline()) return Result.Offline
        return try {
            classify(username, transport.get(keysUrl(username)))
        } catch (e: CancellationException) {
            throw e
        } catch (e: OfflineModeException) {
            Result.Offline
        } catch (e: Exception) {
            Result.Failed(e.message ?: e.javaClass.simpleName)
        }
    }

    /** The real request, on the shared client every other lookup uses. */
    object NetworkTransport : Transport {
        override suspend fun get(url: String): Answer = withContext(Dispatchers.IO) {
            val response = HttpClientFactory.client().get(url) {
                header("Accept", "application/pgp-keys, text/plain;q=0.9, */*;q=0.5")
            }
            val status = response.status.value
            // Only a success body is read; a 404 or an error page is never needed.
            val body: ByteArray = if (status in 200..299) response.bytesCapped(MAX_RESPONSE_BYTES) else ByteArray(0)
            Answer(status, response.headers["Content-Type"], body)
        }
    }
}
