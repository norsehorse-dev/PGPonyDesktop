// DesktopCardOps.kt
// PGPony Desktop — D7: the glue between the crypto surfaces and the card. DesktopCardOps
// answers "can a card handle this?" (PKESK ↔ card-backed-row matching, mirroring the Android
// EncryptDecryptViewModel routing + the 3.1.0 A1 subkey rule via the paired rings), and
// CardOpDialog is the one PIN-and-run surface every card operation goes through: reader
// picker (when more than one), PW1 entry with the cache honored (a live cached PIN skips the
// prompt entirely — the session's verify() refreshes/clears the cache, same chokepoint as
// Android), wrong-PIN retry with the tries-remaining message, and the touch-confirm hint
// (YubiKeys with UIF sit silent until tapped).
//
// D11b — localized. CardOpRequest.title arrives ALREADY RESOLVED from the calling screen
// (it is a sentence that screen composed), so it is shown as-is and never re-translated.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.crypto.card.CardPinCache
import com.pgpony.android.crypto.card.OpenPgpCardException
import com.pgpony.android.crypto.card.OpenPgpCardSession
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import java.io.ByteArrayInputStream

object DesktopCardOps {

    /** A card-backed keyring row that can decrypt a given message, plus its paired ring. */
    data class CardDecryptMatch(val entity: PGPKeyEntity, val ring: PGPPublicKeyRing)

    /**
     * Does [encryptedBytes] carry a PKESK addressed to a PAIRED card-backed key? Scans the
     * message's key IDs against each card-backed row's stored public ring (primary AND
     * subkeys — offline-primary cards keep only subkeys in their slots). Null when no card
     * can help; software decrypt failures then surface unchanged.
     */
    suspend fun matchCardDecryptKey(
        encryptedBytes: ByteArray,
        repo: DesktopKeyRepository
    ): CardDecryptMatch? {
        val keyIds = runCatching { pkeskKeyIds(encryptedBytes) }.getOrDefault(emptyList())
        if (keyIds.isEmpty()) return null
        val cardRows = repo.allKeys().filter { it.isCardBacked && it.armoredPublicKey != null }
        for (row in cardRows) {
            val ring = repo.loadPublicKeyRing(row.fingerprint) ?: continue
            if (keyIds.any { ring.getPublicKey(it) != null }) {
                return CardDecryptMatch(row, ring)
            }
        }
        return null
    }

    private fun pkeskKeyIds(encryptedBytes: ByteArray): List<Long> {
        val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(encryptedBytes))
        val factory = JcaPGPObjectFactory(decoder)
        var obj = factory.nextObject()
        while (obj != null) {
            if (obj is PGPEncryptedDataList) {
                return obj.encryptedDataObjects.asSequence()
                    .filterIsInstance<PGPPublicKeyEncryptedData>()
                    .map { it.keyID }
                    .toList()
            }
            obj = factory.nextObject()
        }
        return emptyList()
    }

    /** True when [entity] signs on a card (paired, with the public cert present). */
    fun signsOnCard(entity: PGPKeyEntity?): Boolean =
        entity != null && entity.isCardBacked && entity.armoredPublicKey != null && !entity.isKeyPair
}

/**
 * One pending card operation: [run] receives a connected, SELECTed session plus the verified
 * PW1 bytes and does the actual work (it may set screen state via its closure). Create via
 * the screen's `requestCardOp` helper.
 */
class CardOpRequest(
    val title: String,
    val run: suspend (OpenPgpCardSession, ByteArray) -> Unit
)

/**
 * The PIN-and-run dialog. With a live cached PIN it fires immediately (one frame of
 * "working…" instead of a prompt). Wrong PIN re-prompts with the card's tries-remaining
 * message — the cache was already cleared by the session.
 */
@Composable
fun CardOpDialog(request: CardOpRequest, onDone: (ok: Boolean, message: String?) -> Unit) {
    val scope = rememberCoroutineScope()
    var readers by remember { mutableStateOf(DesktopCardReader.listReaders()) }
    var reader by remember {
        mutableStateOf(readers.firstOrNull { it.cardPresent }?.name ?: readers.firstOrNull()?.name)
    }
    var readerMenu by remember { mutableStateOf(false) }
    var pin by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var autoTried by remember { mutableStateOf(false) }

    fun execute(pinBytes: ByteArray) {
        working = true
        error = null
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    DesktopCardReader.withCard(reader) { session ->
                        session.select()
                        // Blocking bridge into the suspend op: the card work itself is
                        // synchronous APDU I/O, so runBlocking on the IO thread is the
                        // intended shape here.
                        kotlinx.coroutines.runBlocking { request.run(session, pinBytes) }
                    }
                }
                onDone(true, null)
            } catch (e: OpenPgpCardException.WrongPin) {
                pin = ""
                error = e.message // cache already cleared by session.verify
                working = false
            } catch (t: Throwable) {
                working = false
                onDone(false, t.message ?: t::class.simpleName)
            }
        }
    }

    // A live cached PIN runs without prompting (the Android cached-tap behavior).
    LaunchedEffect(Unit) {
        if (!autoTried) {
            autoTried = true
            CardPinCache.retrieve()?.let { cached ->
                execute(cached.toByteArray(Charsets.UTF_8))
            }
        }
    }

    BrandDialog(
        onDismissRequest = { if (!working) onDone(false, null) },
        title = request.title,
        content = {
            Column(modifier = Modifier.fillMaxWidth()) {
                if (readers.size > 1) {
                    WrapRow {
                        // D12 — the menu moves inside a Box with its anchor. As a bare sibling it
                        // would be a WrapRow item of its own, and a popup measures to nothing, so
                        // it would take a slot and throw the gaps out. Boxed, it stays one item
                        // and keeps anchoring to the button it opens from.
                        Box {
                            OutlinedButton(onClick = { readerMenu = true }, enabled = !working) {
                                Text(reader ?: tr("d_cards_choose_reader"))
                            }
                            DropdownMenu(expanded = readerMenu, onDismissRequest = { readerMenu = false }) {
                                readers.forEach { r ->
                                    DropdownMenuItem(
                                        text = {
                                            Text(if (r.cardPresent) tr("d_cards_reader_with_card", r.name) else r.name)
                                        },
                                        onClick = { reader = r.name; readerMenu = false }
                                    )
                                }
                            }
                        }
                        TextButton(onClick = {
                            readers = DesktopCardReader.listReaders()
                            if (reader !in readers.map { it.name }) {
                                reader = readers.firstOrNull { it.cardPresent }?.name
                                    ?: readers.firstOrNull()?.name
                            }
                        }, enabled = !working) { Text(tr("d_cards_rescan")) }
                    }
                    Spacer(Modifier.height(8.dp))
                }
                if (readers.isEmpty()) {
                    Text(
                        tr("d_cards_no_reader_detected"),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(Modifier.height(6.dp))
                    TextButton(onClick = { readers = DesktopCardReader.listReaders()
                        reader = readers.firstOrNull { it.cardPresent }?.name }) { Text(tr("d_cards_rescan")) }
                }
                OutlinedTextField(
                    value = pin, onValueChange = { pin = it },
                    label = { Text(tr("d_cards_pin_pw1")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !working,
                    isError = error != null,
                    modifier = Modifier.fillMaxWidth()
                )
                error?.let {
                    Spacer(Modifier.height(4.dp))
                    Text(it, color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall)
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    if (working) tr("d_cards_talking_touch") else tr("d_cards_pin_scope_note"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = !working && pin.isNotBlank() && readers.isNotEmpty(),
                onClick = { execute(pin.toByteArray(Charsets.UTF_8)) }
            ) { Text(if (working) tr("d_common_working") else tr("d_common_run")) }
        },
        dismissButton = {
            TextButton(onClick = { onDone(false, null) }, enabled = !working) { Text(tr("common_button_cancel")) }
        }
    )
}
