// BackupDialogs.kt
// PGPony Desktop — D6 backup UI. Export enforces the format's forced re-entry: the recovery
// code must be re-typed (normalization applied — typos like l/I→1, O→0 are fine) before the
// file can be written, so a backup can never exist whose code wasn't saved. Restore detects
// PGPony vs OpenKeychain backups by armor header and picks the right code format.
//
// D11b — localized. The two AWT FileDialog helpers take their title as a parameter: the
// create = { } lambda runs OUTSIDE composition, so a tr() call in there would not resubscribe
// when the language changes. The caller resolves the title in the composable body instead.

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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.awt.AwtWindow
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.pgpony.android.backup.CrockfordBase32
import kotlinx.coroutines.launch
import java.awt.FileDialog
import java.awt.Frame
import java.io.File
import java.time.LocalDate

@Composable
fun ExportBackupDialog(state: DesktopState, onDismiss: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    val backup = remember { DesktopBackupService(state.repository) }
    val recovery = remember { CrockfordBase32.generate() }
    var reentry by remember { mutableStateOf("") }
    var showSave by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val reentryMatches = CrockfordBase32.normalize(reentry) == recovery.canonical

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(tr("d_backup_export_title")) },
        text = {
            Column {
                Text(
                    tr("d_backup_export_intro"),
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    recovery.grouped,
                    style = MaterialTheme.typography.titleLarge,
                    fontFamily = FontFamily.Monospace
                )
                TextButton(onClick = {
                    clipboard.setText(AnnotatedString(recovery.grouped))
                    state.status = tr("d_backup_code_copied")
                }) { Text(tr("backup_code_copy")) }
                Spacer(Modifier.height(6.dp))
                Text(
                    tr("d_backup_reenter_warning"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    value = reentry, onValueChange = { reentry = it },
                    label = { Text(tr("backup_confirm_label")) }, singleLine = true,
                    isError = reentry.isNotBlank() && !reentryMatches,
                    modifier = Modifier.fillMaxWidth()
                )
                error?.let {
                    Spacer(Modifier.height(6.dp))
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = reentryMatches && !busy, onClick = { showSave = true }) {
                Text(if (busy) tr("d_common_working") else tr("d_backup_save_action"))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !busy) { Text(tr("common_button_cancel")) }
        }
    )

    val saveDialogTitle = tr("d_backup_save_dialog_title")
    if (showSave) {
        BackupSaveDialog(
            saveDialogTitle,
            "pgpony-backup-${LocalDate.now()}.${DesktopBackupService.FILE_EXTENSION}"
        ) { file ->
            showSave = false
            if (file != null) scope.launch {
                busy = true
                try {
                    file.writeBytes(backup.exportBackup(recovery.canonical))
                    state.status = tr("d_backup_saved_status", file.name)
                    onDismiss()
                } catch (t: Throwable) {
                    error = t.message ?: tr("d_backup_failed")
                } finally {
                    busy = false
                }
            }
        }
    }
}

@Composable
fun RestoreBackupDialog(
    state: DesktopState,
    initialFile: File? = null,
    onDismiss: () -> Unit
) {
    val scope = rememberCoroutineScope()
    val backup = remember { DesktopBackupService(state.repository) }
    var pickedFile by remember { mutableStateOf(initialFile) }
    var kind by remember { mutableStateOf(BackupKind.UNKNOWN) }
    var code by remember { mutableStateOf("") }
    var showPicker by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var report by remember { mutableStateOf<MergeReport?>(null) }

    // D9 — when opened on a .pgpony file, detect its kind up front (the picker path does this
    // too, but a preset file skips the picker).
    androidx.compose.runtime.LaunchedEffect(initialFile) {
        if (initialFile != null) {
            kind = runCatching { backup.detectKind(initialFile.readBytes()) }.getOrDefault(BackupKind.UNKNOWN)
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(tr("d_restore_title")) },
        text = {
            Column(modifier = Modifier.heightIn(max = 480.dp).verticalScroll(rememberScrollState())) {
                Row {
                    OutlinedButton(onClick = { showPicker = true }, enabled = !busy) {
                        Text(pickedFile?.name ?: tr("d_restore_choose_file"))
                    }
                    Spacer(Modifier.width(8.dp))
                    if (kind != BackupKind.UNKNOWN) Text(
                        when (kind) {
                            BackupKind.PGPONY -> tr("d_restore_kind_pgpony")
                            BackupKind.OPENKEYCHAIN -> tr("d_restore_kind_okc")
                            else -> ""
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = code, onValueChange = { code = it },
                    label = {
                        Text(
                            if (kind == BackupKind.OPENKEYCHAIN) tr("d_restore_code_label_okc")
                            else tr("restore_code_label")
                        )
                    },
                    singleLine = true, enabled = !busy,
                    modifier = Modifier.fillMaxWidth()
                )
                Text(
                    tr("d_restore_note"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                error?.let {
                    Spacer(Modifier.height(6.dp))
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                report?.let { r ->
                    Spacer(Modifier.height(8.dp))
                    Text(
                        tr("d_restore_done_status", r.summary()),
                        style = MaterialTheme.typography.titleSmall
                    )
                    listOf(
                        "restore_added" to r.added, "restore_upgraded" to r.upgraded,
                        "restore_updated" to r.updated, "restore_unchanged" to r.unchanged,
                        "restore_failed" to r.failed
                    ).forEach { (labelKey, list) ->
                        if (list.isNotEmpty()) {
                            Spacer(Modifier.height(4.dp))
                            Text(tr(labelKey), style = MaterialTheme.typography.labelLarge)
                            list.forEach {
                                Text(
                                    "· ${it.label}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            if (report == null) TextButton(
                enabled = !busy && pickedFile != null && code.isNotBlank(),
                onClick = {
                    scope.launch {
                        busy = true; error = null
                        try {
                            val bytes = pickedFile!!.readBytes()
                            report = when (backup.detectKind(bytes)) {
                                BackupKind.OPENKEYCHAIN -> backup.restoreOpenKeychainBackup(bytes, code)
                                else -> backup.restoreBackup(bytes, code)
                            }
                            state.reload()
                            state.status = tr("d_restore_status", report!!.summary())
                        } catch (t: Throwable) {
                            error = t.message ?: tr("d_restore_failed")
                        } finally {
                            busy = false
                        }
                    }
                }
            ) { Text(if (busy) tr("d_common_working") else tr("restore_run")) }
            else TextButton(onClick = onDismiss) { Text(tr("common_button_done")) }
        },
        dismissButton = {
            if (report == null) {
                TextButton(onClick = onDismiss, enabled = !busy) { Text(tr("common_button_cancel")) }
            }
        }
    )

    val openDialogTitle = tr("d_restore_open_dialog_title")
    if (showPicker) {
        BackupOpenDialog(openDialogTitle) { file ->
            showPicker = false
            pickedFile = file
            kind = file?.let { runCatching { backup.detectKind(it.readBytes()) }.getOrDefault(BackupKind.UNKNOWN) }
                ?: BackupKind.UNKNOWN
            report = null; error = null
        }
    }
}

@Composable
private fun BackupSaveDialog(
    title: String,
    suggestedName: String,
    onResult: (File?) -> Unit
) = AwtWindow(
    create = {
        object : FileDialog(null as Frame?, title, SAVE) {
            init { file = suggestedName }
            override fun setVisible(visible: Boolean) {
                super.setVisible(visible)
                if (visible) onResult(file?.let { File(directory, it) })
            }
        }
    },
    dispose = FileDialog::dispose
)

@Composable
private fun BackupOpenDialog(title: String, onResult: (File?) -> Unit) = AwtWindow(
    create = {
        object : FileDialog(null as Frame?, title, LOAD) {
            override fun setVisible(visible: Boolean) {
                super.setVisible(visible)
                if (visible) onResult(file?.let { File(directory, it) })
            }
        }
    },
    dispose = FileDialog::dispose
)
