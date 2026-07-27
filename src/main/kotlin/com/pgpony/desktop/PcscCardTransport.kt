// PcscCardTransport.kt
// PGPony Desktop — D7: the PC/SC link. The desktop counterpart of Android's
// IsoDepCardTransport: implements the vendored CardTransport seam over javax.smartcardio, so
// the ENTIRE vendored card stack (OpenPgpCardSession, KDF handling, CardDecryptService,
// CardSigningService, CardKeygenService, the BC signer/decryptor bridges) runs unchanged
// against a USB reader. jdk.smartcardio has shipped in the jlink image since D1.
//
// DesktopCardReader is the OpenPgpCardReader analog: reader discovery plus a
// one-operation-per-connection runner. USB removes NFC's one-tap constraint, but the session
// discipline stays deliberately identical (plan D7): connect, run ONE user-triggered
// operation, disconnect — no long-lived card handles to go stale or block other apps
// (gpg-agent, scdaemon) from the reader.
//
// D11b — the exception messages built here ARE user-facing: OpenPgpCardException.message is
// what every card surface shows verbatim, so they are keys. tr() is not @Composable and
// resolves fine off the UI thread, which is where all of this runs (Dispatchers.IO).

package com.pgpony.desktop

import com.pgpony.android.crypto.card.CardTransport
import com.pgpony.android.crypto.card.OpenPgpCardException
import com.pgpony.android.crypto.card.OpenPgpCardSession
import javax.smartcardio.CardChannel
import javax.smartcardio.CardException
import javax.smartcardio.CardTerminal
import javax.smartcardio.CommandAPDU
import javax.smartcardio.TerminalFactory

class PcscCardTransport(private val channel: CardChannel) : CardTransport {

    override fun transceive(commandApdu: ByteArray): ByteArray = try {
        // transmit() returns data + SW; the vendored session handles 61xx GET RESPONSE and
        // 6Cxx retries itself (and PC/SC stacks that do their own 61xx handling simply hand
        // the session a completed response — the chaining loop then no-ops).
        channel.transmit(CommandAPDU(commandApdu)).bytes
    } catch (e: CardException) {
        val msg = e.message ?: ""
        // A card pulled mid-exchange maps onto the Android vocabulary the session's error
        // handling (and every screen's error copy) already speaks.
        if (msg.contains("removed", ignoreCase = true) ||
            msg.contains("SCARD_W_REMOVED_CARD", ignoreCase = true)
        ) {
            throw OpenPgpCardException.TagLost(tr("d_card_err_unplugged"), e)
        }
        throw OpenPgpCardException.Communication(tr("d_card_err_io", msg), e)
    }
}

/**
 * A throwable and every cause under it, on one line.
 *
 * The JDK's PC/SC layer wraps everything: `sun.security.smartcardio.PCSCTerminals` catches a
 * `PCSCException` and rethrows `CardException("list() failed", cause)`. So `e.message` is the
 * useless wrapper and the `SCARD_E_*` code — the single fact that identifies the fault — sits one
 * level down. 1.0.1 added a diagnostic and then printed the wrapper, which is how a Windows report
 * came back reading "list() failed" and said nothing.
 *
 * SCARD_E_SHARING_VIOLATION (something else holds the reader exclusively) and SCARD_E_NO_SERVICE
 * (the resource-manager context is dead) need opposite fixes and are indistinguishable without it.
 */
internal fun causeChain(t: Throwable): String {
    val parts = ArrayList<String>()
    var cur: Throwable? = t
    val seen = HashSet<Throwable>()          // a self-referential cause would otherwise spin
    while (cur != null && seen.add(cur)) {
        val msg = cur.message?.takeIf { it.isNotBlank() }
        parts += if (msg != null) "${cur.javaClass.simpleName}: $msg" else cur.javaClass.simpleName
        cur = cur.cause
    }
    return parts.joinToString(" <- ")
}

/**
 * Reader discovery + the per-operation session runner. All entry points are blocking PC/SC
 * I/O — call from Dispatchers.IO (the screen helpers do).
 */
object DesktopCardReader {

    /** One attached reader and whether a card is currently present in it. */
    data class ReaderInfo(val name: String, val cardPresent: Boolean)

    /**
     * Why the last [listReaders] call came back empty, or null when it succeeded.
     *
     * An empty list is ambiguous and that ambiguity shipped: a machine with nothing plugged in
     * and a machine whose PC/SC layer threw look identical to every caller, so 1.0.0 rendered
     * both as one sentence about no reader being detected. A Windows bug report where the module
     * was present, the service running and the reader recognised by the OS could not be taken
     * any further, because the only fact that would have identified it was discarded here.
     *
     * Plain @Volatile rather than Compose state: the UI reads it immediately after calling
     * [listReaders], in the same recomposition, so there is nothing to observe.
     */
    @Volatile
    var lastListError: String? = null
        private set

    /**
     * How many times a PC/SC call is attempted before giving up, and the pause between tries.
     * Three attempts adds at most ~240 ms to a failure and nothing at all to a success.
     */
    private const val PCSC_ATTEMPTS = 3
    private const val PCSC_BACKOFF_MS = 120L

    /**
     * Set when a PC/SC call FAILED and then succeeded on a retry. STICKY for the life of the
     * process — deliberately not cleared by a later clean call, because the whole point is that
     * an intermittent fault leaves a trace someone can still find afterwards. Nothing in the UI
     * reads it (a transient the app recovered from is not the user's problem); `pgpony card-info`
     * prints it.
     *
     * This matters more than the retry itself. A retry that hides the failure would make the
     * fault unobservable and permanent.
     */
    @Volatile
    var lastRecovery: String? = null
        private set

    /**
     * Run a PC/SC call, retrying on failure.
     *
     * Not a blind retry. OpenJDK's PCSCTerminals.list() responds to SCARD_E_NO_SERVICE and
     * SCARD_E_SERVICE_STOPPED by resetting its cached context id to 0 and THEN throwing — so the
     * call that fails is also the call that repairs the context, and the next one re-establishes
     * it. Without a retry the user sees a hard failure the library was already prepared to
     * recover from, which is what a Windows box did: enumeration succeeded, the session open
     * threw, and everything worked afterwards with no code change.
     *
     * A short backoff also covers the other candidate, SCARD_E_SHARING_VIOLATION, where another
     * process holds the reader for a moment.
     *
     * Blocking sleeps are fine here: every entry point on this object is already documented as
     * blocking PC/SC I/O called from Dispatchers.IO.
     */
    private fun <T> pcscRetry(block: () -> T): T {
        var failure: Exception? = null
        for (attempt in 1..PCSC_ATTEMPTS) {
            try {
                val value = block()
                if (attempt > 1) {
                    lastRecovery = "recovered on attempt $attempt of $PCSC_ATTEMPTS " +
                        "after ${causeChain(failure!!)}"
                }
                return value
            } catch (e: Exception) {
                failure = e
                if (attempt < PCSC_ATTEMPTS) Thread.sleep(PCSC_BACKOFF_MS)
            }
        }
        throw failure!!
    }

    /**
     * The attached PC/SC readers. Empty (never throws) when the PC/SC layer is unavailable —
     * on Linux that usually means pcscd isn't running; macOS and Windows ship the service
     * natively. Check [lastListError] to tell "none attached" from "PC/SC failed".
     */
    fun listReaders(): List<ReaderInfo> = try {
        val found = pcscRetry { TerminalFactory.getDefault().terminals().list() }.map { t ->
            ReaderInfo(t.name, runCatching { t.isCardPresent }.getOrDefault(false))
        }
        lastListError = null
        found
    } catch (e: Exception) {
        // The SCARD_* name IS the diagnosis, and the callers' never-throws contract is kept.
        // SCARD_E_NO_SERVICE (the resource manager is not running) and
        // SCARD_E_NO_READERS_AVAILABLE (it is running and has nothing) are different problems
        // with different fixes, and both used to arrive as the same empty list.
        lastListError = causeChain(e)
        emptyList()
    }

    /**
     * Run [operation] against the card in [readerName] (or the first reader with a card when
     * null). Opens a fresh connection, hands the operation an OpenPgpCardSession on a
     * PcscCardTransport, and ALWAYS disconnects afterward — the conservative one-operation
     * session discipline. The operation is responsible for session.select() (matching the
     * Android startOperation contract).
     *
     * Throws OpenPgpCardException.Communication with a user-ready message when no reader or
     * no card is available.
     */
    fun <T> withCard(readerName: String?, operation: (OpenPgpCardSession) -> T): T {
        val terminal = findTerminal(readerName)
        val card = try {
            // "*" negotiates the protocol; USB CCID OpenPGP tokens (YubiKey 5, Token2) come
            // up as T=1.
            // Retried too: SCARD_E_SHARING_VIOLATION here means another process held the
            // reader for a moment, which is exactly the transient a second attempt clears.
            pcscRetry { terminal.connect("*") }
        } catch (e: CardException) {
            throw OpenPgpCardException.Communication(
                // causeChain, not e.message: a connect failure is where an exclusive-access
                // holder shows up as SCARD_E_SHARING_VIOLATION, and the JDK wraps that too.
                tr("d_card_err_connect", terminal.name, causeChain(e)), e
            )
        }
        try {
            return operation(OpenPgpCardSession(PcscCardTransport(card.basicChannel)))
        } finally {
            // reset=false: leave the card state alone for other clients; our session made no
            // assumption it can't re-establish with the next SELECT anyway.
            runCatching { card.disconnect(false) }
        }
    }

    private fun findTerminal(readerName: String?): CardTerminal {
        val terminals = try {
            pcscRetry { TerminalFactory.getDefault().terminals().list() }
        } catch (e: Exception) {
            throw OpenPgpCardException.Communication(
                // The two suffixes carry their own leading space: the XML reader does not
                // trim, and ja swaps the ASCII parentheses for full-width ones.
                tr("d_card_err_no_service") +
                    (if (System.getProperty("os.name").lowercase().contains("linux"))
                        tr("d_card_err_pcscd_hint") else "") +
                    tr("d_card_err_detail_suffix", causeChain(e)),
                e
            )
        }
        if (terminals.isEmpty()) {
            throw OpenPgpCardException.Communication(tr("d_cards_no_reader_detected"))
        }
        val named = readerName?.let { want -> terminals.firstOrNull { it.name == want } }
        if (readerName != null && named == null) {
            throw OpenPgpCardException.Communication(
                tr("d_card_err_reader_gone", readerName)
            )
        }
        val terminal = named
            ?: terminals.firstOrNull { runCatching { it.isCardPresent }.getOrDefault(false) }
            ?: terminals.first()
        val present = runCatching { terminal.isCardPresent }.getOrDefault(false)
        if (!present) {
            throw OpenPgpCardException.Communication(
                tr("d_card_err_no_card", terminal.name)
            )
        }
        return terminal
    }
}
