// PairDialog.kt
// PGPony Desktop 3.0.0, F1: "Pair with another computer". One computer waits, the other
// connects to the address it shows; the joining computer shows a six-digit code and asks whether
// the waiting one shows the same, and the waiting computer's user types the code the joining one
// shows (docs/PAIRING_PROTOCOL.md, section 4). Then either side can send public keys, key pairs or
// a full backup; the receiver picks what to take and sees each item, as read from its bytes,
// before anything is written. Nothing is remembered: closing the dialog ends the session and
// wipes its keys, and no socket is written on the UI thread. The protocol is
// docs/PAIRING_PROTOCOL.md in PGPonyAndroid (vendor/app-pair); PairController holds the logic
// this dialog drives.

package com.pgpony.desktop

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pgpony.android.pair.PairAnswer
import com.pgpony.android.pair.PairAttempt
import com.pgpony.android.pair.PairException
import com.pgpony.android.pair.PairFailure
import com.pgpony.android.pair.PairInfo
import com.pgpony.android.pair.PairItem
import com.pgpony.android.pair.PairMessage
import com.pgpony.android.pair.PairOffer
import com.pgpony.android.pair.PairResult
import com.pgpony.android.pair.PairRole
import com.pgpony.android.pair.PairSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.net.InetAddress
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap

private sealed class PairStage {
    object Choose : PairStage()
    /** [peer] is set once a device connected and the handshake runs. */
    class Hosting(val window: PairController.HostWindow, val peer: String? = null) : PairStage()
    object Joining : PairStage()
    class Compare(val attempt: PairAttempt, val peer: String, val waiting: Boolean = false) : PairStage()
    class Paired(val session: PairSession, val peer: String) : PairStage()
    class Failed(val message: String) : PairStage()
}

/** Runs [block] on a daemon thread, so a socket write never runs on the UI thread. */
private fun inBackground(block: () -> Unit) {
    Thread({ runCatching(block) }, "pgpony-pair-ui").apply { isDaemon = true }.start()
}

/** The clipboard's text, trimmed, or null when it holds none. */
private fun clipboardText(): String? = runCatching {
    Toolkit.getDefaultToolkit().systemClipboard.getData(DataFlavor.stringFlavor) as? String
}.getOrNull()?.trim()?.takeIf { it.isNotEmpty() }

/** The message a failed attempt shows. */
internal fun pairFailureMessage(e: Throwable): String {
    val failure = (e as? PairException)?.failure ?: return tr("d_pair_fail_closed")
    return when (failure) {
        PairFailure.REFUSED -> tr("d_pair_fail_refused")
        PairFailure.HANDSHAKE -> tr("d_pair_fail_handshake")
        PairFailure.TIMEOUT -> e.message?.takeIf { it == tr("d_pair_err_window_expired") } ?: tr("d_pair_fail_timeout")
        PairFailure.VERSION -> tr("d_pair_fail_version")
        PairFailure.PROTOCOL -> tr("d_pair_fail_protocol")
        PairFailure.BUSY, PairFailure.CLOSED -> tr("d_pair_fail_closed")
    }
}

/** The message a failed join shows: a refused or cut connection may mean the window was taken. */
internal fun joinFailureMessage(e: Throwable): String =
    if (PairController.windowMayBeTaken(e)) tr("d_pair_fail_window_taken") else pairFailureMessage(e)

@Composable
fun PairDialog(state: DesktopState, onDismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    val controller = remember { PairController(state.repository, state.edits) }
    var stage by remember { mutableStateOf<PairStage>(PairStage.Choose) }

    // Whatever is open when the dialog goes away is closed: the listener, the attempt, the session.
    // Nothing here waits on the network: a peer that stopped reading cannot freeze the window.
    fun teardown() {
        when (val s = stage) {
            is PairStage.Hosting -> s.window.close()
            is PairStage.Compare -> inBackground { s.attempt.reject() }
            is PairStage.Paired -> s.session.endAsync()
            else -> {}
        }
    }
    DisposableEffect(Unit) { onDispose { teardown() } }

    fun fail(e: Throwable) {
        stage = PairStage.Failed(pairFailureMessage(e))
    }

    fun startCompare(attempt: PairAttempt, peer: String) {
        val compare = PairStage.Compare(attempt, peer)
        stage = compare
        attempt.peerRefused.thenAccept { failure ->
            scope.launch {
                val s = stage
                if (s is PairStage.Compare && s.attempt === attempt) stage = PairStage.Failed(pairFailureMessage(PairException(failure, "")))
            }
        }
    }

    fun host() {
        val window = try {
            PairController.HostWindow()
        } catch (e: Exception) {
            fail(e)
            return
        }
        stage = PairStage.Hosting(window)
        scope.launch {
            try {
                // The screen leaves "waiting" as soon as a device connects, and says which one.
                val peer = withContext(Dispatchers.IO) { window.awaitConnection() }
                if (stage !is PairStage.Hosting) return@launch
                stage = PairStage.Hosting(window, peer)
                val attempt = withContext(Dispatchers.IO) { window.handshake() }
                startCompare(attempt, peer)
            } catch (e: Exception) {
                if (stage is PairStage.Hosting) fail(e)
            }
        }
    }

    fun confirm(compare: PairStage.Compare) {
        stage = PairStage.Compare(compare.attempt, compare.peer, waiting = true)
        scope.launch {
            try {
                val session = withContext(Dispatchers.IO) { compare.attempt.confirm() }
                stage = PairStage.Paired(session, compare.peer)
            } catch (e: Exception) {
                fail(e)
            }
        }
    }

    fun refuse(compare: PairStage.Compare, message: String) {
        inBackground { compare.attempt.reject() }
        stage = PairStage.Failed(message)
    }

    val s = stage
    BrandDialog(
        onDismissRequest = onDismiss,
        title = tr("d_pair_title"),
        content = {
            Column(Modifier.fillMaxWidth().heightIn(max = 560.dp).verticalScroll(rememberScrollState())) {
                when (s) {
                    PairStage.Choose -> {
                        Text(tr("d_pair_intro"), style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(12.dp))
                        Row {
                            OutlinedButton(onClick = { host() }) { Text(tr("d_pair_host")) }
                            Spacer(Modifier.width(Spacing.Small))
                            OutlinedButton(onClick = { stage = PairStage.Joining }) { Text(tr("d_pair_join")) }
                        }
                    }
                    is PairStage.Hosting -> if (s.peer == null) HostingPane(s.window) else {
                        Text(tr("d_pair_host_connected", s.peer), style = MaterialTheme.typography.bodyMedium)
                    }
                    PairStage.Joining -> JoiningPane(
                        controller,
                        onAttempt = { startCompare(it.attempt, it.peer) },
                        onError = { stage = PairStage.Failed(joinFailureMessage(it)) }
                    )
                    is PairStage.Compare -> if (s.attempt.role == PairRole.HOST) {
                        HostComparePane(
                            s,
                            onMatch = { confirm(s) },
                            onCancel = { refuse(s, tr("d_pair_fail_you_cancelled")) },
                            onTooManyWrong = { refuse(s, tr("d_pair_fail_typed_wrong")) }
                        )
                    } else {
                        ComparePane(
                            s,
                            onMatch = { confirm(s) },
                            onDiffer = { refuse(s, tr("d_pair_fail_you_refused")) }
                        )
                    }
                    is PairStage.Paired -> SessionPane(state, controller, s.session, s.peer, onEnded = { stage = PairStage.Failed(tr("d_pair_ended")) })
                    is PairStage.Failed -> {
                        Text(s.message, style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.height(12.dp))
                        OutlinedButton(onClick = { stage = PairStage.Choose }) { Text(tr("d_pair_again")) }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(if (s is PairStage.Paired) tr("d_pair_end") else tr("common_button_close"))
            }
        }
    )
}

@Composable
private fun HostingPane(window: PairController.HostWindow) {
    val (primary, others) = remember(window) { window.addresses() }
    var showOthers by remember(window) { mutableStateOf(false) }
    val closesAt = remember(window) {
        DateTimeFormatter.ofPattern("HH:mm").format(
            Instant.ofEpochMilli(window.openedAt + PairController.WINDOW_MS).atZone(ZoneId.systemDefault())
        )
    }
    if (primary == null) {
        Text(tr("d_pair_no_address"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
        return
    }
    Text(tr("d_pair_host_waiting"), style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.height(8.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(primary, style = MaterialTheme.typography.headlineSmall, fontFamily = FontFamily.Monospace)
        Spacer(Modifier.width(Spacing.Small))
        TextButton(onClick = { DesktopClipboard.copy(primary, secret = false) }) { Text(tr("common_button_copy")) }
    }
    // Virtual machine and VPN adapters have addresses too; they stay out of the way until needed.
    if (others.isNotEmpty()) {
        TextButton(onClick = { showOthers = !showOthers }) {
            Text(if (showOthers) tr("d_pair_other_addresses_hide") else tr("d_pair_other_addresses", others.size))
        }
        if (showOthers) {
            Text(tr("d_pair_other_addresses_note"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            others.forEach { address ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(address, style = MaterialTheme.typography.bodyLarge, fontFamily = FontFamily.Monospace)
                    Spacer(Modifier.width(Spacing.Small))
                    TextButton(onClick = { DesktopClipboard.copy(address, secret = false) }) { Text(tr("common_button_copy")) }
                }
            }
        }
    }
    // The invite: a phone scans it, another computer can paste it. Either way the joiner also
    // checks this window's key before the codes are compared.
    val invite = remember(window) { window.invite() }
    val qr = remember(invite) {
        invite?.let { QrCode.encodeToPng(it.toUri(), 360) }?.let { org.jetbrains.skia.Image.makeFromEncoded(it).toComposeImageBitmap() }
    }
    if (invite != null && qr != null) {
        Spacer(Modifier.height(8.dp))
        Image(bitmap = qr, contentDescription = tr("d_pair_invite_note"), modifier = Modifier.size(180.dp))
        Text(tr("d_pair_invite_note"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        TextButton(onClick = { DesktopClipboard.copy(invite.toUri(), secret = false) }) { Text(tr("d_pair_copy_invite")) }
    }
    Spacer(Modifier.height(8.dp))
    Text(tr("d_pair_host_closes", closesAt), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(4.dp))
    Text(tr("d_pair_firewall"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun JoiningPane(controller: PairController, onAttempt: (PairController.Connection) -> Unit, onError: (Throwable) -> Unit) {
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var bad by remember { mutableStateOf(false) }
    var working by remember { mutableStateOf(false) }
    Text(tr("d_pair_join_intro"), style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = text,
        onValueChange = { text = it; bad = false },
        label = { Text(tr("d_pair_join_label")) },
        placeholder = { Text("192.168.1.20:49152") },
        singleLine = true,
        isError = bad,
        enabled = !working,
        modifier = Modifier.fillMaxWidth()
    )
    if (bad) Text(if (PairController.looksLikeInvite(text)) tr("d_pair_bad_invite") else tr("d_pair_bad_address"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    TextButton(enabled = !working, onClick = { clipboardText()?.let { text = it; bad = false } }) { Text(tr("common_button_paste")) }
    Spacer(Modifier.height(8.dp))
    OutlinedButton(enabled = !working && text.isNotBlank(), onClick = {
        working = true
        scope.launch {
            try {
                val target = withContext(Dispatchers.IO) { PairController.target(text) }
                if (target == null) {
                    bad = true
                    return@launch
                }
                // Not cancelled half way: an attempt that connected after the dialog closed is
                // refused rather than left open.
                val connection = withContext(Dispatchers.IO + NonCancellable) { controller.connect(target) }
                if (!isActive) {
                    inBackground { connection.attempt.reject() }
                    return@launch
                }
                onAttempt(connection)
            } catch (e: Exception) {
                if (isActive) onError(e)
            } finally {
                working = false
            }
        }
    }) { Text(if (working) tr("d_common_working") else tr("d_pair_connect")) }
}

/** The joining side: the code, and whether the other computer shows the same one. */
@Composable
private fun ComparePane(compare: PairStage.Compare, onMatch: () -> Unit, onDiffer: () -> Unit) {
    Text(tr("d_pair_peer_address", compare.peer), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(8.dp))
    Text(tr("d_pair_compare_body"), style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.height(12.dp))
    Text(compare.attempt.code, fontSize = 40.sp, fontWeight = FontWeight.SemiBold, fontFamily = FontFamily.Monospace)
    Spacer(Modifier.height(12.dp))
    if (compare.waiting) {
        Text(tr("d_pair_waiting_other"), style = MaterialTheme.typography.bodyMedium)
    } else {
        Row {
            OutlinedButton(onClick = onMatch) { Text(tr("d_pair_codes_match")) }
            Spacer(Modifier.width(Spacing.Small))
            OutlinedButton(onClick = onDiffer) { Text(tr("d_pair_codes_differ")) }
        }
    }
}

/**
 * The waiting side: its user types the code the joining computer shows instead of pressing a
 * "same code" button, so the pairing cannot be confirmed when the other screen shows no code
 * (docs/PAIRING_PROTOCOL.md, section 4). This side's own code stays visible for the other user
 * to compare.
 */
@Composable
private fun HostComparePane(compare: PairStage.Compare, onMatch: () -> Unit, onCancel: () -> Unit, onTooManyWrong: () -> Unit) {
    var typed by remember(compare.attempt) { mutableStateOf("") }
    var wrong by remember(compare.attempt) { mutableStateOf(false) }
    var tries by remember(compare.attempt) { mutableStateOf(0) }
    Text(tr("d_pair_peer_address", compare.peer), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(8.dp))
    if (compare.waiting) {
        Text(tr("d_pair_waiting_other"), style = MaterialTheme.typography.bodyMedium)
        return
    }
    Text(tr("d_pair_compare_host_body"), style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = typed,
        onValueChange = { v -> typed = v.filter { it in '0'..'9' || it == ' ' }.take(7); wrong = false },
        label = { Text(tr("d_pair_typed_code_label")) },
        singleLine = true,
        isError = wrong,
        textStyle = MaterialTheme.typography.headlineSmall.copy(fontFamily = FontFamily.Monospace),
        modifier = Modifier.fillMaxWidth()
    )
    if (wrong) Text(tr("d_pair_typed_code_wrong"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    Spacer(Modifier.height(8.dp))
    Row {
        OutlinedButton(enabled = typed.count { it in '0'..'9' } == 6, onClick = {
            if (compare.attempt.matchesTypedCode(typed)) {
                onMatch()
            } else {
                tries += 1
                if (tries >= PairController.TYPED_CODE_TRIES) onTooManyWrong() else {
                    wrong = true
                    typed = ""
                }
            }
        }) { Text(tr("d_pair_typed_code_confirm")) }
        Spacer(Modifier.width(Spacing.Small))
        OutlinedButton(onClick = onCancel) { Text(tr("common_button_cancel")) }
    }
    Spacer(Modifier.height(12.dp))
    Text(tr("d_pair_compare_host_own"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Text(compare.attempt.code, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace)
}

/** An offer from the other side, waiting for this user's picks. */
private class Incoming(val offer: PairOffer)

@Composable
private fun SessionPane(state: DesktopState, controller: PairController, session: PairSession, peer: String, onEnded: () -> Unit) {
    val scope = rememberCoroutineScope()
    var peerName by remember { mutableStateOf<String?>(null) }
    // What the other side can import (its INFO); nothing is offered that it cannot take.
    var peerInfo by remember { mutableStateOf<PairInfo?>(null) }
    val log = remember { mutableStateListOf<String>() }
    var incoming by remember { mutableStateOf<Incoming?>(null) }
    var outgoing by remember { mutableStateOf<PairController.Prepared?>(null) }
    var pendingResults by remember { mutableStateOf(0) }
    var progress by remember { mutableStateOf<String?>(null) }
    // Accepted ids and sizes; the reader checks arriving items against it, so it is live.
    val expected = remember { ConcurrentHashMap<Int, Long>() }
    val acceptedItems = remember { ConcurrentHashMap<Int, PairItem>() }
    var backupCode by remember { mutableStateOf("") }
    // Received items that passed the checks, each waiting for this user's Add or Skip.
    val received = remember { mutableStateListOf<PairController.Received>() }

    fun sendResult(result: PairResult) {
        scope.launch { runCatching { withContext(Dispatchers.IO) { session.sendResult(result) } } }
    }

    // Nothing is written before the user accepted the preview; the RESULT goes out after.
    fun decide(r: PairController.Received, add: Boolean) {
        received.remove(r)
        val item = r.item
        if (!add) {
            log += tr("d_pair_skipped", item.name)
            sendResult(PairResult(item.id, false, tr("d_pair_skipped_reason")))
            return
        }
        scope.launch {
            val result = try {
                val summary = withContext(Dispatchers.IO) { controller.apply(item, r.bytes, backupCode) }
                log += tr("d_pair_result_ok", item.name, summary)
                PairResult(item.id, true)
            } catch (e: Exception) {
                val why = e.message ?: e.javaClass.simpleName
                log += tr("d_pair_result_failed", item.name, why)
                PairResult(item.id, false, why)
            }
            state.reload()
            runCatching { withContext(Dispatchers.IO) { session.sendResult(result) } }
        }
    }

    fun onMessage(m: PairMessage) {
        when (m) {
            is PairMessage.Info -> {
                peerName = m.info.name.takeIf { it.isNotBlank() }
                peerInfo = m.info
            }
            is PairMessage.Offer -> incoming = Incoming(m.offer)
            is PairMessage.Answer -> {
                val prepared = outgoing ?: return
                val accepted = prepared.items.filter { it.id in m.answer.accept }
                if (accepted.isEmpty()) {
                    log += tr("d_pair_declined")
                    outgoing = null
                    return
                }
                pendingResults = accepted.size
                scope.launch {
                    try {
                        for (item in accepted) {
                            progress = tr("d_pair_sending", item.name)
                            withContext(Dispatchers.IO) { session.sendItem(item.id, prepared.payloads.getValue(item.id)) }
                        }
                    } catch (e: Exception) {
                        log += pairFailureMessage(e)
                    } finally {
                        progress = null
                    }
                }
            }
            is PairMessage.Item -> {
                val item = acceptedItems[m.id] ?: return
                expected.remove(m.id)
                // Checked against the offer first; only an item that passes is shown for Add or Skip.
                scope.launch {
                    try {
                        received += withContext(Dispatchers.IO) { controller.check(item, m.bytes) }
                    } catch (e: Exception) {
                        val why = e.message ?: e.javaClass.simpleName
                        log += tr("d_pair_result_failed", item.name, why)
                        sendResult(PairResult(item.id, false, why))
                    }
                }
            }
            is PairMessage.Result -> {
                val name = outgoing?.items?.firstOrNull { it.id == m.result.id }?.name ?: "#${m.result.id}"
                log += if (m.result.ok) tr("d_pair_sent_ok", name) else tr("d_pair_result_failed", name, m.result.error ?: "")
                pendingResults -= 1
                if (pendingResults <= 0) outgoing = null
            }
            PairMessage.Bye -> onEnded()
        }
    }

    // The reader: one thread for the session, handing each message to the UI.
    LaunchedEffect(session) {
        withContext(Dispatchers.IO) {
            session.sendInfo(
                PairInfo(runCatching { InetAddress.getLocalHost().hostName }.getOrDefault(""), "PGPony Desktop ${AppVersion.VERSION}", PairItem.KINDS)
            )
        }
        try {
            while (true) {
                val m = withContext(Dispatchers.IO) {
                    session.receive(expected) { id, n ->
                        val item = acceptedItems[id]
                        if (item != null && item.size > 0) progress = tr("d_pair_receiving", item.name, (n * 100 / item.size).toInt())
                    }
                }
                progress = null
                onMessage(m)
                if (m == PairMessage.Bye) break
            }
        } catch (e: Exception) {
            onEnded()
        }
    }

    // No name: a whole sentence per language, since a bare "the other computer" would need a
    // different grammatical case in each slot it filled.
    Text(peerName?.let { tr("d_pair_paired_with", it) } ?: tr("d_pair_paired_unnamed"), style = MaterialTheme.typography.titleMedium)
    // The name comes from the other side; the address is what this computer actually talks to.
    Text(tr("d_pair_peer_address", peer), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(8.dp))

    val inc = incoming
    val first = received.firstOrNull()
    if (first != null) {
        ReceivedPane(first) { add -> decide(first, add) }
    } else if (inc != null) {
        IncomingPane(inc.offer, peerName, backupCode, { backupCode = it }) { accept ->
            val picked = inc.offer.items.filter { it.id in accept }
            picked.forEach { expected[it.id] = it.size; acceptedItems[it.id] = it }
            incoming = null
            scope.launch { runCatching { withContext(Dispatchers.IO) { session.sendAnswer(PairAnswer(picked.map { it.id })) } } }
        }
    } else if (outgoing != null) {
        Text(progress ?: tr("d_pair_waiting_answer"), style = MaterialTheme.typography.bodyMedium)
        outgoing?.recoveryCode?.let { code ->
            Spacer(Modifier.height(8.dp))
            Text(tr("d_pair_backup_code_tell"), style = MaterialTheme.typography.bodyMedium)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(code, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace)
                Spacer(Modifier.width(Spacing.Small))
                TextButton(onClick = {
                    // The code opens the backup, so it counts as a secret and auto-clear applies.
                    DesktopClipboard.copy(code, secret = true)
                    state.status = tr("d_backup_code_copied")
                }) { Text(tr("common_button_copy")) }
            }
        }
    } else {
        progress?.let {
            Text(it, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
        }
        SendPane(controller, peerInfo) { prepared ->
            outgoing = prepared
            scope.launch { runCatching { withContext(Dispatchers.IO) { session.sendOffer(PairOffer(prepared.items)) } }.onFailure { log += pairFailureMessage(it) } }
        }
    }

    if (log.isNotEmpty()) {
        Spacer(Modifier.height(12.dp))
        log.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}

@Composable
private fun SendPane(controller: PairController, peer: PairInfo?, onPrepared: (PairController.Prepared) -> Unit) {
    val scope = rememberCoroutineScope()
    var candidates by remember { mutableStateOf<List<PairController.Outgoing>>(emptyList()) }
    val picked = remember { mutableStateListOf<PairController.Outgoing>() }
    var pass by remember { mutableStateOf("") }
    var pass2 by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) { candidates = withContext(Dispatchers.IO) { controller.candidates() } }

    val needsPass = picked.any { it is PairController.Outgoing.KeyPair && !it.protected }
    val passOk = !needsPass || (pass.isNotEmpty() && pass == pass2)

    Text(tr("d_pair_send_heading"), style = MaterialTheme.typography.titleSmall)
    Spacer(Modifier.height(4.dp))
    // A side that has not said what it takes (no INFO yet, or an INFO without accepts) takes all three.
    fun takes(kind: String) = peer?.takes(kind) ?: true
    if (takes(PairItem.KEY_PAIR)) {
        OutgoingGroup(tr("d_pair_group_keypairs"), candidates.filterIsInstance<PairController.Outgoing.KeyPair>(), picked, !working)
    }
    if (takes(PairItem.PUBLIC_KEY)) {
        OutgoingGroup(tr("d_pair_group_public"), candidates.filterIsInstance<PairController.Outgoing.PublicKey>(), picked, !working)
    }
    if (takes(PairItem.BACKUP)) {
        OutgoingGroup(tr("d_pair_group_backup"), candidates.filter { it is PairController.Outgoing.Backup }, picked, !working)
    }
    if (needsPass) {
        Spacer(Modifier.height(8.dp))
        Text(tr("d_pair_transfer_pass_note"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        OutlinedTextField(
            value = pass, onValueChange = { pass = it }, label = { Text(tr("d_pair_transfer_pass")) },
            singleLine = true, visualTransformation = PasswordVisualTransformation(), enabled = !working,
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = pass2, onValueChange = { pass2 = it }, label = { Text(tr("d_pair_transfer_pass_repeat")) },
            singleLine = true, visualTransformation = PasswordVisualTransformation(), enabled = !working,
            isError = pass2.isNotEmpty() && pass != pass2, modifier = Modifier.fillMaxWidth()
        )
    }
    error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    Spacer(Modifier.height(8.dp))
    OutlinedButton(enabled = picked.isNotEmpty() && passOk && !working, onClick = {
        working = true
        error = null
        scope.launch {
            try {
                onPrepared(withContext(Dispatchers.IO) { controller.prepare(picked.toList(), pass.takeIf { needsPass }) })
            } catch (e: Exception) {
                error = e.message ?: e.javaClass.simpleName
            } finally {
                working = false
            }
        }
    }) { Text(if (working) tr("d_common_working") else tr("d_pair_send")) }
}

@Composable
private fun OutgoingGroup(
    title: String, list: List<PairController.Outgoing>, picked: MutableList<PairController.Outgoing>, enabled: Boolean
) {
    if (list.isEmpty()) return
    Text(title, style = MaterialTheme.typography.labelLarge)
    list.forEach { o ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = o in picked, enabled = enabled, onCheckedChange = { if (it) picked += o else picked -= o })
            Text(o.name, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun IncomingPane(
    offer: PairOffer, from: String?, backupCode: String, onBackupCode: (String) -> Unit, onAnswer: (List<Int>) -> Unit
) {
    // An item of a kind this version does not know is not shown, so it can never be accepted.
    val items = remember(offer) { offer.items.filter { it.kind in PairItem.KINDS } }
    // Nothing is picked until the user picks it.
    val chosen = remember(offer) { mutableStateListOf<Int>() }
    Text(from?.let { tr("d_pair_incoming_heading", it) } ?: tr("d_pair_incoming_heading_unnamed"), style = MaterialTheme.typography.titleSmall)
    items.forEach { item ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = item.id in chosen, onCheckedChange = { if (it) chosen += item.id else chosen -= item.id })
            Column {
                Text(
                    when (item.kind) {
                        PairItem.KEY_PAIR -> tr("d_pair_kind_keypair", item.name)
                        PairItem.PUBLIC_KEY -> tr("d_pair_kind_public", item.name)
                        else -> tr("d_pair_item_backup")
                    },
                    style = MaterialTheme.typography.bodyMedium
                )
                item.fingerprint?.takeIf { item.kind != PairItem.BACKUP }?.let { fp ->
                    Text(
                        tr("d_pair_incoming_fingerprint", fp.uppercase().chunked(4).joinToString(" ")),
                        style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
    val wantsBackup = items.any { it.kind == PairItem.BACKUP && it.id in chosen }
    if (wantsBackup) {
        Spacer(Modifier.height(4.dp))
        OutlinedTextField(
            value = backupCode, onValueChange = onBackupCode, label = { Text(tr("d_pair_backup_code_label")) },
            singleLine = true, modifier = Modifier.fillMaxWidth()
        )
        TextButton(onClick = { clipboardText()?.let(onBackupCode) }) { Text(tr("common_button_paste")) }
    }
    Spacer(Modifier.height(8.dp))
    Row {
        OutlinedButton(enabled = chosen.isNotEmpty() && (!wantsBackup || backupCode.isNotBlank()), onClick = { onAnswer(chosen.toList()) }) {
            Text(tr("d_pair_accept"))
        }
        Spacer(Modifier.width(Spacing.Small))
        OutlinedButton(onClick = { onAnswer(emptyList()) }) { Text(tr("d_pair_decline")) }
    }
}

/**
 * A received item that passed the checks, as read from its own bytes (not as the offer named
 * it): the key's fingerprint and user IDs, or what restoring the backup does. Nothing is written
 * until the user chooses Add (or Restore).
 */
@Composable
private fun ReceivedPane(received: PairController.Received, onDecide: (Boolean) -> Unit) {
    val key = received.keys.firstOrNull()
    if (received.item.kind == PairItem.BACKUP || key == null) {
        Text(tr("d_pair_received_backup"), style = MaterialTheme.typography.bodyMedium)
    } else {
        Text(
            tr(if (key.hasPrivateKey) "d_pair_received_keypair" else "d_pair_received_public"),
            style = MaterialTheme.typography.titleSmall
        )
        Spacer(Modifier.height(4.dp))
        key.userIds.forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
        Text(
            key.fingerprint.uppercase().chunked(4).joinToString(" "),
            style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace
        )
        if (key.inKeyring) {
            Text(tr("d_pair_received_in_keyring"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
    Spacer(Modifier.height(8.dp))
    Row {
        OutlinedButton(onClick = { onDecide(true) }) {
            Text(tr(if (received.item.kind == PairItem.BACKUP) "d_pair_received_restore" else "d_pair_received_add"))
        }
        Spacer(Modifier.width(Spacing.Small))
        OutlinedButton(onClick = { onDecide(false) }) { Text(tr("d_pair_received_skip")) }
    }
}
