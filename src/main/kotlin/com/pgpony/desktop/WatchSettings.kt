// WatchSettings.kt
// PGPony Desktop — D18 (2.0.0 §3c): the watch-folders Settings surface.
//
// Kept beside no logic on purpose — the engine is WatchFolderService, the model WatchRule — so
// this file is only Compose: the master toggle, the rules list (enable / remove per rule), a
// recent-outcomes pane, and the add-a-rule dialog. Lives here rather than in SettingsScreen.kt
// so that screen's edit stays one SectionCard call (the UpdateCheck / SshAgent pattern).
//
// The section says, in copy, what the feature's security rests on: encrypt-only, public keys
// only, no passphrase or PIN ever — so a rule that runs while you're away can at worst encrypt.

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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp

@Composable
fun WatchSection(state: DesktopState) {
    var rules by remember { mutableStateOf(WatchRulesStore.load().rules) }
    var showAdd by remember { mutableStateOf(false) }

    fun reloadRules() { rules = WatchRulesStore.load().rules }

    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = state.watchEnabled, onCheckedChange = { state.enableWatch(it) })
        Spacer(Modifier.width(Spacing.Small))
        Text(tr("d_settings_watch_enable"), style = MaterialTheme.typography.bodyMedium)
    }

    Spacer(Modifier.height(Spacing.Medium))
    SubHeading(tr("d_settings_watch_rules"))

    if (rules.isEmpty()) {
        Text(
            tr("d_settings_watch_no_rules"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    } else {
        rules.forEach { rule ->
            Card(
                shape = RoundedCornerShape(Radius.Small),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)
            ) {
                Column(modifier = Modifier.padding(Spacing.Medium)) {
                    Text(
                        "${rule.folder}  ·  ${rule.glob}",
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        tr("d_settings_watch_rule_summary", rule.recipients.size,
                            rule.outputDir ?: tr("d_settings_watch_beside_source")),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    WrapRow(horizontalSpacing = Spacing.Small, verticalSpacing = Spacing.Tight) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = rule.enabled,
                                onCheckedChange = {
                                    WatchRulesStore.setRuleEnabled(rule.id, it); reloadRules(); state.refreshWatch()
                                }
                            )
                            Text(tr("d_settings_watch_rule_on"), style = MaterialTheme.typography.bodySmall)
                        }
                        if (rule.deleteOriginal) BrandBadge(tr("d_settings_watch_deletes"))
                        if (rule.armor) BrandBadge("ASCII")
                        TextButton(onClick = {
                            WatchRulesStore.remove(rule.id); reloadRules(); state.refreshWatch()
                        }) { Text(tr("d_common_remove")) }
                    }
                }
            }
        }
    }

    Spacer(Modifier.height(Spacing.Small))
    OutlinedButton(onClick = { showAdd = true }) { Text(tr("d_settings_watch_add_rule")) }

    // Recent outcomes — the results pane. Newest first, bounded by the service.
    if (WatchFolderService.outcomes.isNotEmpty()) {
        Spacer(Modifier.height(Spacing.Medium))
        SubHeading(tr("d_settings_watch_recent"))
        Column(modifier = Modifier.heightIn(max = 220.dp).verticalScroll(rememberScrollState())) {
            WatchFolderService.outcomes.forEach { o ->
                Text(
                    (if (o.ok) "✓ " else "✗ ") + o.source + (o.output?.let { " → $it" } ?: "") +
                        "  ·  " + o.detail,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (o.ok) MaterialTheme.colorScheme.onSurfaceVariant
                    else MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(vertical = 1.dp)
                )
            }
        }
    }

    if (showAdd) {
        AddRuleDialog(
            state = state,
            onDismiss = { showAdd = false },
            onSaved = { showAdd = false; reloadRules(); state.refreshWatch() }
        )
    }
}

@Composable
private fun AddRuleDialog(state: DesktopState, onDismiss: () -> Unit, onSaved: () -> Unit) {
    var folder by remember { mutableStateOf("") }
    var glob by remember { mutableStateOf("*") }
    var outputDir by remember { mutableStateOf("") }
    var deleteOriginal by remember { mutableStateOf(false) }
    var armor by remember { mutableStateOf(false) }
    val selected = remember { mutableStateOf(setOf<String>()) }

    // Usable recipients — the Android availableRecipients rule (a card row needs its public cert).
    val recipients = state.keys.filter {
        !it.isRevoked && !it.isExpired && (!it.isCardBacked || it.armoredPublicKey != null)
    }

    val canSave = folder.isNotBlank() && selected.value.isNotEmpty()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(tr("d_settings_watch_add_rule")) },
        text = {
            Column(modifier = Modifier.heightIn(max = 420.dp).verticalScroll(rememberScrollState())) {
                OutlinedTextField(
                    value = folder, onValueChange = { folder = it },
                    label = { Text(tr("d_settings_watch_folder")) },
                    trailingIcon = {
                        TextButton(onClick = { pickDirectoryPath()?.let { folder = it } }) {
                            Text(tr("d_settings_watch_browse"))
                        }
                    },
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(Spacing.Small))
                OutlinedTextField(
                    value = glob, onValueChange = { glob = it },
                    label = { Text(tr("d_settings_watch_glob")) },
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(Spacing.Small))
                OutlinedTextField(
                    value = outputDir, onValueChange = { outputDir = it },
                    label = { Text(tr("d_settings_watch_output")) },
                    trailingIcon = {
                        TextButton(onClick = { pickDirectoryPath()?.let { outputDir = it } }) {
                            Text(tr("d_settings_watch_browse"))
                        }
                    },
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )

                Spacer(Modifier.height(Spacing.Medium))
                SubHeading(tr("encrypt_recipients_label"))
                if (recipients.isEmpty()) {
                    Text(tr("d_settings_watch_no_recipients"), style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error)
                }
                recipients.forEach { key ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = key.fingerprint in selected.value,
                            onCheckedChange = { on ->
                                selected.value = if (on) selected.value + key.fingerprint
                                else selected.value - key.fingerprint
                            }
                        )
                        Text(
                            key.userEmail.ifBlank { key.userID }.ifBlank { key.fingerprint.takeLast(16) },
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }

                Spacer(Modifier.height(Spacing.Small))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = armor, onCheckedChange = { armor = it })
                    Text(tr("d_settings_watch_armor"), style = MaterialTheme.typography.bodySmall)
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = deleteOriginal, onCheckedChange = { deleteOriginal = it })
                    Text(tr("d_settings_watch_delete_original"), style = MaterialTheme.typography.bodySmall)
                }
                if (deleteOriginal) {
                    Text(tr("d_settings_watch_delete_warning"), style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = canSave,
                onClick = {
                    WatchRulesStore.add(
                        WatchRule(
                            id = "rule-${System.nanoTime()}",
                            folder = folder.trim(),
                            glob = glob.trim().ifBlank { "*" },
                            recipients = selected.value.toList(),
                            outputDir = outputDir.trim().ifBlank { null },
                            deleteOriginal = deleteOriginal,
                            armor = armor
                        )
                    )
                    onSaved()
                }
            ) { Text(tr("common_button_save")) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("common_button_cancel")) } }
    )
}

/** A modal native directory chooser (Swing, cross-platform for folders). Null on cancel.
 *  Shared with the Files tab's "Add folder…" button (CryptoScreen), same package. */
internal fun pickDirectoryPath(): String? {
    val chooser = javax.swing.JFileChooser().apply {
        fileSelectionMode = javax.swing.JFileChooser.DIRECTORIES_ONLY
    }
    return if (chooser.showOpenDialog(null) == javax.swing.JFileChooser.APPROVE_OPTION) {
        chooser.selectedFile?.absolutePath
    } else null
}
