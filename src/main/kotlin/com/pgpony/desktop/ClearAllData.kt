// ClearAllData.kt
// PGPony Desktop 3.0.0 (plan 3.2): Clear All Data, Android 4.2.0 RC5's gauntlet. Step one names
// every key that will be destroyed, offers a backup and asks for an acknowledgement; step two asks
// for a second acknowledgement and the typed word, then holds the button for five seconds. The
// typed word is asked here whatever the "Protect destructive actions" switch says, as on Android.
//
// Reset to first run: every key (Recently Deleted included) with its material, the Autocrypt and
// API client tables, every desktop setting (the whole app/pgpony/desktop preferences node, which
// holds the key server list, network, SSH agent, watch folder and password store settings), the
// watch rules file, the agent socket directory, and the held card PIN and passphrases. The
// password store itself and anything the user saved elsewhere are theirs and stay. The app then
// closes, because every screen holds settings it read at launch.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Checkbox
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.nio.file.Files
import java.nio.file.Path
import java.util.prefs.Preferences
import kotlin.system.exitProcess

object ClearAllData {

    /** The preferences node every desktop setting lives under. */
    internal const val PREFS_NODE = "app/pgpony/desktop"

    /** Test hook: where the files beside the database live. */
    internal var dataDirOverride: Path? = null

    /** Test hook: a scratch preferences root instead of the user's. */
    internal var prefsRootOverride: Preferences? = null

    const val COUNTDOWN_SECONDS = 5

    suspend fun run(edits: DesktopKeyEdits) = withContext(Dispatchers.IO) {
        if (dataDirOverride == null) {
            SshAgentService.stop()
            WatchFolderService.stop()
        }
        edits.purgeEverything()
        if (dataDirOverride == null) {
            SessionPolicy.clearAll()
            ShimBridge.stop()
        }
        val dir = dataDirOverride ?: Config.dataDir
        Files.deleteIfExists(dir.resolve("watch-rules.json"))
        Files.deleteIfExists(dir.resolve("keyring.json"))
        deleteTree(dir.resolve("agent"))
        deleteTree(dir.resolve("keys"))
        val root = prefsRootOverride ?: Preferences.userRoot()
        if (root.nodeExists(PREFS_NODE)) {
            root.node(PREFS_NODE).removeNode()
            runCatching { root.flush() }
        }
    }

    private fun deleteTree(path: Path) {
        if (!Files.exists(path)) return
        Files.walk(path).use { walk ->
            walk.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }
}

/**
 * The two-step confirmation. [onBackup] closes this flow and opens the backup export. On success
 * a final dialog says the app will close.
 */
@Composable
fun ClearAllDataFlow(state: DesktopState, onBackup: () -> Unit, onDismiss: () -> Unit) {
    var step by remember { mutableStateOf(1) }
    var ack1 by remember { mutableStateOf(false) }
    var ack2 by remember { mutableStateOf(false) }
    var typed by remember { mutableStateOf("") }
    var countdown by remember { mutableStateOf(ClearAllData.COUNTDOWN_SECONDS) }
    var running by remember { mutableStateOf(false) }
    var done by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val word = tr("settings_data_clear_type_word")
    val armed = ack2 && typed.trim() == word
    val doomed = state.keys + state.deletedKeys

    LaunchedEffect(armed) {
        countdown = ClearAllData.COUNTDOWN_SECONDS
        if (armed) {
            while (countdown > 0) {
                delay(1000)
                countdown--
            }
        }
    }

    when {
        done -> BrandDialog(
            onDismissRequest = {},
            title = tr("settings_data_clear_success"),
            content = { Text(tr("d_settings_clear_done_body")) },
            confirmButton = { TextButton(onClick = { exitProcess(0) }) { Text(tr("common_button_ok")) } }
        )
        step == 1 -> BrandDialog(
            onDismissRequest = onDismiss,
            title = tr("settings_data_clear_step1_title"),
            destructive = true,
            content = {
                Column(Modifier.heightIn(max = 480.dp).verticalScroll(rememberScrollState())) {
                    Text(tr("settings_data_clear_step1_body"))
                    if (doomed.isNotEmpty()) {
                        Spacer(Modifier.height(Spacing.Medium))
                        Text(
                            tr("settings_data_clear_key_list_header_format", doomed.size),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(Modifier.height(Spacing.Tight))
                        doomed.forEach { key ->
                            Text(
                                tr("d_settings_clear_key_row", key.userID.ifBlank { key.shortFingerprint }, key.shortFingerprint),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    Spacer(Modifier.height(Spacing.Medium))
                    Text(
                        tr("d_settings_clear_scope_note"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(Spacing.Medium))
                    OutlinedButton(onClick = onBackup, modifier = Modifier.fillMaxWidth()) {
                        Text(tr("settings_data_clear_backup_button"))
                    }
                    Spacer(Modifier.height(Spacing.Small))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = ack1, onCheckedChange = { ack1 = it })
                        Text(tr("d_settings_clear_ack1"), style = MaterialTheme.typography.bodyMedium)
                    }
                }
            },
            confirmButton = {
                TextButton(enabled = ack1, onClick = { step = 2 }) {
                    Text(tr("common_button_continue"), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = onDismiss) { Text(tr("common_button_cancel")) } }
        )
        else -> BrandDialog(
            onDismissRequest = { if (!running) onDismiss() },
            title = tr("settings_data_clear_step2_title"),
            destructive = true,
            content = {
                Column {
                    Text(tr("settings_data_clear_step2_body"))
                    Spacer(Modifier.height(Spacing.Small))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = ack2, onCheckedChange = { ack2 = it }, enabled = !running)
                        Text(tr("settings_data_clear_ack2_label"), style = MaterialTheme.typography.bodyMedium)
                    }
                    Spacer(Modifier.height(Spacing.Small))
                    OutlinedTextField(
                        value = typed,
                        onValueChange = { typed = it },
                        singleLine = true,
                        enabled = !running,
                        label = { Text(tr("settings_data_clear_type_label_format", word)) },
                        modifier = Modifier.fillMaxWidth()
                    )
                    error?.let {
                        Spacer(Modifier.height(Spacing.Small))
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = armed && countdown == 0 && !running,
                    onClick = {
                        running = true
                        error = null
                        state.clearAllData(
                            onDone = { done = true },
                            onError = { running = false; error = it }
                        )
                    }
                ) {
                    val label = tr("settings_data_clear_step2_confirm")
                    Text(
                        when {
                            running -> tr("d_common_working")
                            armed && countdown > 0 -> tr("d_settings_clear_countdown", label, countdown)
                            else -> label
                        },
                        color = MaterialTheme.colorScheme.error
                    )
                }
            },
            dismissButton = { TextButton(onClick = onDismiss, enabled = !running) { Text(tr("common_button_cancel")) } }
        )
    }
}
