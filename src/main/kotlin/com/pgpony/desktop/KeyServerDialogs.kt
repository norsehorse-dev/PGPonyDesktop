// KeyServerDialogs.kt
// PGPony Desktop — D4 keyserver UI: the server-search dialog (Keyring toolbar) and the
// publish dialog (key detail). Both ride the vendored network stack — WKD → directory →
// Hagrid lookup order via KeyServerRepository, per-server VKS/HKP publish via
// MultiKeyServerService — so lookup provenance, the R5 key-type warning, and the
// verification-email flow all match Android.
//
// D11b — localized. Each publish outcome is a WHOLE sentence with the server label passed as
// an argument: the label leads in English but not in every locale, so it cannot be a prefix
// glued on in Kotlin.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.keyserver.KeyServer
import com.pgpony.android.keyserver.KeyServerDirectory
import com.pgpony.android.network.KeyLookupResult
import com.pgpony.android.network.KeyServerRepository
import com.pgpony.android.keyserver.PublishOutcome
import kotlinx.coroutines.launch

// ── Search ─────────────────────────────────────────────────────────────

/**
 * Search key servers (and WKD) by email or fingerprint; preview the hit's identity before
 * importing. Fingerprint detection: ≥16 hex chars once spaces are stripped.
 */
@Composable
fun SearchKeyServersDialog(state: DesktopState, onDismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    var query by remember { mutableStateOf("") }
    var searching by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<KeyLookupResult?>(null) }
    var resultUserId by remember { mutableStateOf("") }
    var resultFingerprint by remember { mutableStateOf("") }
    var message by remember { mutableStateOf<String?>(null) }

    fun runSearch() {
        val q = query.trim()
        if (q.isEmpty() || searching) return
        searching = true
        result = null
        message = null
        scope.launch {
            try {
                val cleaned = q.filter { !it.isWhitespace() }
                val isFingerprint = cleaned.length >= 16 &&
                    cleaned.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
                val hit = if (isFingerprint) {
                    KeyServerRepository.shared.findByFingerprint(cleaned)
                } else {
                    KeyServerRepository.shared.findByEmail(q)
                }
                if (hit == null) {
                    message = tr("d_search_none")
                } else {
                    val parsed = runCatching {
                        PGPCryptoService.shared.importArmoredKey(hit.armoredKey)
                    }.getOrNull()
                    resultUserId = parsed?.userID?.ifBlank { tr("d_keydetail_no_user_id") }
                        ?: tr("d_search_unparseable")
                    resultFingerprint = parsed?.fingerprint?.uppercase()
                        ?.chunked(4)?.joinToString(" ") ?: ""
                    result = hit
                }
            } catch (t: Throwable) {
                message = tr("d_search_failed", t.message ?: t::class.simpleName.orEmpty())
            } finally {
                searching = false
            }
        }
    }

    AlertDialog(
        onDismissRequest = { if (!searching) onDismiss() },
        title = { Text(tr("d_search_servers_title")) },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                OutlinedTextField(
                    value = query, onValueChange = { query = it },
                    label = { Text(tr("import_keyserver_query_label")) },
                    singleLine = true,
                    enabled = !searching,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    tr("d_search_lookup_order"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (searching) {
                    Spacer(Modifier.height(10.dp))
                    Text(
                        tr("import_keyserver_search_button_in_progress"),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                message?.let {
                    Spacer(Modifier.height(10.dp))
                    Text(it, style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                result?.let { hit ->
                    Spacer(Modifier.height(10.dp))
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(10.dp)) {
                            Text(resultUserId, style = MaterialTheme.typography.titleSmall)
                            if (resultFingerprint.isNotBlank()) {
                                Text(
                                    resultFingerprint,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Text(
                                tr("d_search_found_via", hit.source.displayName),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        tr("d_search_trust_warning"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        },
        confirmButton = {
            val hit = result
            if (hit != null) {
                TextButton(onClick = {
                    state.importArmoredText(hit.armoredKey)
                    onDismiss()
                }) { Text(tr("d_common_import")) }
            } else {
                TextButton(onClick = { runSearch() }, enabled = !searching && query.isNotBlank()) {
                    Text(tr("import_keyserver_search_button"))
                }
            }
        },
        dismissButton = {
            if (result != null) {
                TextButton(onClick = { result = null; runSearch() }, enabled = !searching) {
                    Text(tr("d_search_again"))
                }
            }
            TextButton(onClick = onDismiss, enabled = !searching) { Text(tr("common_button_close")) }
        }
    )
}

// ── Publish ────────────────────────────────────────────────────────────

/**
 * Publish a public key to the publish-enabled directory servers — per-server checkboxes
 * (pre-checked, the Android PublishSheet shape) with the R5 non-coercive warning where a
 * server may not accept this key type. Outcomes render in place; verification-email notes
 * included.
 */
@Composable
fun PublishKeyDialog(state: DesktopState, key: PGPKeyEntity, onDismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    var servers by remember { mutableStateOf<List<KeyServer>>(emptyList()) }
    val checked = remember { mutableStateMapOf<String, Boolean>() }
    var publishing by remember { mutableStateOf(false) }
    var outcomes by remember {
        mutableStateOf<List<Pair<KeyServer, PublishOutcome>>?>(null)
    }

    LaunchedEffect(Unit) {
        servers = runCatching {
            KeyServerDirectory.get(PGPonyApp.instance).readOnce()
        }.getOrDefault(KeyServerDirectory.DEFAULTS)
            .filter { it.publishEnabled }
        servers.forEach { if (it.id !in checked) checked[it.id] = true }
    }

    AlertDialog(
        onDismissRequest = { if (!publishing) onDismiss() },
        title = { Text(tr("d_publish_title")) },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 440.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    key.userID.ifBlank { key.shortFingerprint },
                    style = MaterialTheme.typography.titleSmall
                )
                Spacer(Modifier.height(8.dp))
                if (servers.isEmpty()) {
                    Text(
                        tr("d_publish_no_servers"),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                servers.forEach { server ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = checked[server.id] ?: true,
                            onCheckedChange = { checked[server.id] = it },
                            enabled = !publishing && outcomes == null
                        )
                        Column {
                            Text(server.label, style = MaterialTheme.typography.bodyMedium)
                            if (server.mayNotAccept(key.algorithm)) {
                                Text(
                                    tr("d_publish_may_not_accept", key.algorithm.displayName),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error
                                )
                            }
                        }
                    }
                }
                outcomes?.let { list ->
                    Spacer(Modifier.height(10.dp))
                    list.forEach { (server, outcome) ->
                        val text = when (outcome) {
                            is PublishOutcome.Ok ->
                                tr("d_publish_outcome_ok", server.label) +
                                    if (outcome.pendingEmails.isNotEmpty())
                                        tr(
                                            "d_publish_outcome_pending",
                                            outcome.pendingEmails.joinToString(", ")
                                        )
                                    else ""
                            is PublishOutcome.RejectedKeyType ->
                                tr(
                                    "d_publish_outcome_rejected", server.label,
                                    outcome.httpStatus, key.algorithm.displayName
                                )
                            is PublishOutcome.Failed ->
                                tr("d_publish_outcome_failed", server.label, outcome.message)
                        }
                        Text(
                            text,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (outcome is PublishOutcome.Ok)
                                MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(vertical = 2.dp)
                        )
                    }
                }
                if (outcomes == null) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        tr("d_publish_warning"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        },
        confirmButton = {
            if (outcomes == null) {
                TextButton(
                    enabled = !publishing && servers.any { checked[it.id] == true },
                    onClick = {
                        publishing = true
                        scope.launch {
                            try {
                                outcomes = state.publishTo(
                                    key,
                                    servers.filter { checked[it.id] == true }
                                )
                            } finally {
                                publishing = false
                            }
                        }
                    }
                ) { Text(if (publishing) tr("d_publish_in_progress") else tr("publish_action")) }
            } else {
                TextButton(onClick = onDismiss) { Text(tr("common_button_done")) }
            }
        },
        dismissButton = {
            if (outcomes == null) {
                TextButton(onClick = onDismiss, enabled = !publishing) { Text(tr("common_button_cancel")) }
            }
        }
    )
}
