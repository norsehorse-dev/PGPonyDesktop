// PairDialog.kt
// PGPony Desktop 3.0.0, F1: "Pair with another computer". One computer waits, the other
// connects to the address it shows, both users compare a six-digit code, and then either side
// can send public keys, key pairs or a full backup; the receiver picks what to take. Nothing is
// remembered: closing the dialog ends the session and wipes its keys. The protocol is in
// docs/F1_PAIRING_PROTOCOL.md; PairController holds the logic this dialog drives.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pgpony.pair.PairAnswer
import com.pgpony.pair.PairAttempt
import com.pgpony.pair.PairException
import com.pgpony.pair.PairFailure
import com.pgpony.pair.PairInfo
import com.pgpony.pair.PairItem
import com.pgpony.pair.PairMessage
import com.pgpony.pair.PairOffer
import com.pgpony.pair.PairResult
import com.pgpony.pair.PairSession
import kotlinx.coroutines.Dispatchers
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
    class Hosting(val window: PairController.HostWindow) : PairStage()
    object Joining : PairStage()
    class Compare(val attempt: PairAttempt, val waiting: Boolean = false) : PairStage()
    class Paired(val session: PairSession) : PairStage()
    class Failed(val message: String) : PairStage()
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

@Composable
fun PairDialog(state: DesktopState, onDismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    val controller = remember { PairController(state.repository, state.edits) }
    var stage by remember { mutableStateOf<PairStage>(PairStage.Choose) }

    // Whatever is open when the dialog goes away is closed: the listener, the attempt, the session.
    fun teardown() {
        when (val s = stage) {
            is PairStage.Hosting -> s.window.close()
            is PairStage.Compare -> runCatching { s.attempt.reject() }
            is PairStage.Paired -> {
                s.session.sendBye()
                s.session.close()
            }
            else -> {}
        }
    }
    DisposableEffect(Unit) { onDispose { teardown() } }

    fun fail(e: Throwable) {
        stage = PairStage.Failed(pairFailureMessage(e))
    }

    fun startCompare(attempt: PairAttempt) {
        val compare = PairStage.Compare(attempt)
        stage = compare
        attempt.peerRefused.thenAccept { failure ->
            scope.launch { if (stage === compare) stage = PairStage.Failed(pairFailureMessage(PairException(failure, ""))) }
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
                val attempt = withContext(Dispatchers.IO) { window.accept() }
                startCompare(attempt)
            } catch (e: Exception) {
                if (stage is PairStage.Hosting) fail(e)
            }
        }
    }

    fun confirm(compare: PairStage.Compare) {
        stage = PairStage.Compare(compare.attempt, waiting = true)
        scope.launch {
            try {
                val session = withContext(Dispatchers.IO) { compare.attempt.confirm() }
                stage = PairStage.Paired(session)
            } catch (e: Exception) {
                fail(e)
            }
        }
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
                    is PairStage.Hosting -> HostingPane(s.window)
                    PairStage.Joining -> JoiningPane(controller, onAttempt = { startCompare(it) }, onError = { fail(it) })
                    is PairStage.Compare -> ComparePane(
                        s.attempt.code, s.waiting,
                        onMatch = { confirm(s) },
                        onDiffer = {
                            s.attempt.reject()
                            stage = PairStage.Failed(tr("d_pair_fail_you_refused"))
                        }
                    )
                    is PairStage.Paired -> SessionPane(state, controller, s.session, onEnded = { stage = PairStage.Failed(tr("d_pair_ended")) })
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
    val addresses = remember(window) { window.addresses() }
    val closesAt = remember(window) {
        DateTimeFormatter.ofPattern("HH:mm").format(
            Instant.ofEpochMilli(window.openedAt + PairController.WINDOW_MS).atZone(ZoneId.systemDefault())
        )
    }
    if (addresses.isEmpty()) {
        Text(tr("d_pair_no_address"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
        return
    }
    Text(tr("d_pair_host_waiting"), style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.height(8.dp))
    addresses.forEach { address ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(address, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace)
            Spacer(Modifier.width(Spacing.Small))
            TextButton(onClick = { DesktopClipboard.copy(address, secret = false) }) { Text(tr("common_button_copy")) }
        }
    }
    Spacer(Modifier.height(8.dp))
    Text(tr("d_pair_host_closes", closesAt), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(4.dp))
    Text(tr("d_pair_firewall"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun JoiningPane(controller: PairController, onAttempt: (PairAttempt) -> Unit, onError: (Throwable) -> Unit) {
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
    if (bad) Text(tr("d_pair_bad_address"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    TextButton(enabled = !working, onClick = { clipboardText()?.let { text = it; bad = false } }) { Text(tr("common_button_paste")) }
    Spacer(Modifier.height(8.dp))
    OutlinedButton(enabled = !working && text.isNotBlank(), onClick = {
        working = true
        scope.launch {
            val address = withContext(Dispatchers.IO) { PairController.parse(text) }
            if (address == null) {
                bad = true
                working = false
                return@launch
            }
            try {
                onAttempt(withContext(Dispatchers.IO) { controller.join(address) })
            } catch (e: Exception) {
                onError(e)
            } finally {
                working = false
            }
        }
    }) { Text(if (working) tr("d_common_working") else tr("d_pair_connect")) }
}

@Composable
private fun ComparePane(code: String, waiting: Boolean, onMatch: () -> Unit, onDiffer: () -> Unit) {
    Text(tr("d_pair_compare_body"), style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.height(12.dp))
    Text(code, fontSize = 40.sp, fontWeight = FontWeight.SemiBold, fontFamily = FontFamily.Monospace)
    Spacer(Modifier.height(12.dp))
    if (waiting) {
        Text(tr("d_pair_waiting_other"), style = MaterialTheme.typography.bodyMedium)
    } else {
        Row {
            OutlinedButton(onClick = onMatch) { Text(tr("d_pair_codes_match")) }
            Spacer(Modifier.width(Spacing.Small))
            OutlinedButton(onClick = onDiffer) { Text(tr("d_pair_codes_differ")) }
        }
    }
}

/** An offer from the other side, waiting for this user's picks. */
private class Incoming(val offer: PairOffer)

@Composable
private fun SessionPane(state: DesktopState, controller: PairController, session: PairSession, onEnded: () -> Unit) {
    val scope = rememberCoroutineScope()
    var peerName by remember { mutableStateOf<String?>(null) }
    val log = remember { mutableStateListOf<String>() }
    var incoming by remember { mutableStateOf<Incoming?>(null) }
    var outgoing by remember { mutableStateOf<PairController.Prepared?>(null) }
    var pendingResults by remember { mutableStateOf(0) }
    var progress by remember { mutableStateOf<String?>(null) }
    // Accepted ids and sizes; the reader checks arriving items against it, so it is live.
    val expected = remember { ConcurrentHashMap<Int, Long>() }
    val acceptedItems = remember { ConcurrentHashMap<Int, PairItem>() }
    var backupCode by remember { mutableStateOf("") }

    fun onMessage(m: PairMessage) {
        when (m) {
            is PairMessage.Info -> peerName = m.info.name.ifBlank { tr("d_pair_other_computer") }
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
                scope.launch {
                    val result = try {
                        val summary = withContext(Dispatchers.IO) { controller.apply(item, m.bytes, backupCode) }
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
            session.sendInfo(PairInfo(runCatching { InetAddress.getLocalHost().hostName }.getOrDefault(""), "PGPony Desktop ${AppVersion.VERSION}"))
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

    Text(tr("d_pair_paired_with", peerName ?: tr("d_pair_other_computer")), style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(8.dp))

    val inc = incoming
    if (inc != null) {
        IncomingPane(inc.offer, peerName ?: tr("d_pair_other_computer"), backupCode, { backupCode = it }) { accept ->
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
        SendPane(controller) { prepared ->
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
private fun SendPane(controller: PairController, onPrepared: (PairController.Prepared) -> Unit) {
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
    OutgoingGroup(tr("d_pair_group_keypairs"), candidates.filterIsInstance<PairController.Outgoing.KeyPair>(), picked, !working)
    OutgoingGroup(tr("d_pair_group_public"), candidates.filterIsInstance<PairController.Outgoing.PublicKey>(), picked, !working)
    OutgoingGroup(tr("d_pair_group_backup"), candidates.filter { it is PairController.Outgoing.Backup }, picked, !working)
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
    offer: PairOffer, from: String, backupCode: String, onBackupCode: (String) -> Unit, onAnswer: (List<Int>) -> Unit
) {
    val chosen = remember(offer) { mutableStateListOf<Int>().apply { addAll(offer.items.map { it.id }) } }
    Text(tr("d_pair_incoming_heading", from), style = MaterialTheme.typography.titleSmall)
    offer.items.forEach { item ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = item.id in chosen, onCheckedChange = { if (it) chosen += item.id else chosen -= item.id })
            Text(
                when (item.kind) {
                    PairItem.KEY_PAIR -> tr("d_pair_kind_keypair", item.name)
                    PairItem.PUBLIC_KEY -> tr("d_pair_kind_public", item.name)
                    else -> tr("d_pair_item_backup")
                },
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
    val wantsBackup = offer.items.any { it.kind == PairItem.BACKUP && it.id in chosen }
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
