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
 * Reader discovery + the per-operation session runner. All entry points are blocking PC/SC
 * I/O — call from Dispatchers.IO (the screen helpers do).
 */
object DesktopCardReader {

    /** One attached reader and whether a card is currently present in it. */
    data class ReaderInfo(val name: String, val cardPresent: Boolean)

    /**
     * The attached PC/SC readers. Empty (never throws) when the PC/SC layer is unavailable —
     * on Linux that usually means pcscd isn't running; macOS and Windows ship the service
     * natively.
     */
    fun listReaders(): List<ReaderInfo> = try {
        TerminalFactory.getDefault().terminals().list().map { t ->
            ReaderInfo(t.name, runCatching { t.isCardPresent }.getOrDefault(false))
        }
    } catch (e: Exception) {
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
            terminal.connect("*")
        } catch (e: CardException) {
            throw OpenPgpCardException.Communication(
                tr("d_card_err_connect", terminal.name, e.message.orEmpty()), e
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
            TerminalFactory.getDefault().terminals().list()
        } catch (e: Exception) {
            throw OpenPgpCardException.Communication(
                // The two suffixes carry their own leading space: the XML reader does not
                // trim, and ja swaps the ASCII parentheses for full-width ones.
                tr("d_card_err_no_service") +
                    (if (System.getProperty("os.name").lowercase().contains("linux"))
                        tr("d_card_err_pcscd_hint") else "") +
                    (e.message?.let { tr("d_card_err_detail_suffix", it) } ?: ""),
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
