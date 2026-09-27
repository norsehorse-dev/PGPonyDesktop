// RecentlyDeletedDialog.kt
// PGPony Desktop 3.0.0 (plan 3.1): the recycle bin, Android 4.3.0 (#36) with 4.6.0's public-key
// wording (#58) and 4.7.0's days-left line. Deleted keys stay for DesktopKeyEdits.RETENTION_DAYS,
// restorable, then a launch-time sweep destroys them. Permanent deletion goes through the typed
// confirmation (DestructiveGuard).

package com.pgpony.desktop

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import com.pgpony.android.data.PGPKeyEntity
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

private val BIN_DATE = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM)

fun daysLeftLabel(days: Int): String =
    if (days <= 0) tr("d_recycle_less_than_day") else trQuantity("d_recycle_days_left", days)

@Composable
fun RecentlyDeletedDialog(state: DesktopState, onDismiss: () -> Unit) {
    var purgeTarget by remember { mutableStateOf<PGPKeyEntity?>(null) }
    var confirmEmpty by remember { mutableStateOf(false) }
    val binned = state.deletedKeys

    BrandDialog(
        onDismissRequest = onDismiss,
        title = tr("recycle_bin_title"),
        content = {
            Column(Modifier.heightIn(max = 460.dp).verticalScroll(rememberScrollState())) {
                if (binned.isEmpty()) {
                    Text(tr("recycle_bin_empty_state", DesktopKeyEdits.RETENTION_DAYS))
                }
                binned.forEach { key ->
                    Column(Modifier.fillMaxWidth()) {
                        Text(key.userID.ifBlank { key.shortFingerprint }, style = MaterialTheme.typography.titleSmall)
                        Text(
                            key.formattedFingerprint,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        val deleted = key.deletedAt?.let {
                            tr("recycle_bin_deleted_on", BIN_DATE.format(Instant.ofEpochMilli(it).atZone(ZoneId.systemDefault())))
                        } ?: ""
                        Text(
                            deleted + tr("d_list_separator") + daysLeftLabel(state.edits.daysLeft(key)),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(Spacing.Small), verticalAlignment = Alignment.CenterVertically) {
                            OutlinedButton(onClick = { state.restoreFromBin(key) }) { Text(tr("recycle_bin_restore")) }
                            if (!DestructiveGuard.hidden()) {
                                TextButton(onClick = { purgeTarget = key }) { Text(tr("recycle_bin_delete_now")) }
                            }
                        }
                        Spacer(Modifier.height(Spacing.Medium))
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(tr("common_button_close")) } },
        dismissButton = if (binned.isNotEmpty() && !DestructiveGuard.hidden()) {
            { TextButton(onClick = { confirmEmpty = true }) { Text(tr("recycle_bin_empty_action")) } }
        } else null
    )

    purgeTarget?.let { key ->
        DestructiveConfirmDialog(
            title = tr("recycle_bin_delete_now"),
            body = key.userID.ifBlank { key.shortFingerprint } + "\n\n" + tr("recycle_bin_purge_confirm_body"),
            confirmLabel = tr("recycle_bin_delete_now"),
            onConfirm = { state.purgeFromBin(key); purgeTarget = null },
            onDismiss = { purgeTarget = null }
        )
    }
    if (confirmEmpty) {
        DestructiveConfirmDialog(
            title = tr("recycle_bin_empty_action"),
            body = tr("recycle_bin_empty_confirm_body"),
            confirmLabel = tr("recycle_bin_empty_action"),
            onConfirm = { state.emptyBin(); confirmEmpty = false },
            onDismiss = { confirmEmpty = false }
        )
    }
}
