// KeyDetailDialog.kt
// PGPony Desktop — key detail. D2b: identity, subkeys (vendored SubkeyCapability /
// detectAlgorithm), exports. D2c: mutations — trust level, notes, default signing key,
// expiration editing (vendored KeyExpirationService re-sign), and the Danger Zone revoke flow
// (vendored RevocationService; post-revocation cert export).
// D11b/D11c: localized. Android keys are reused where the English differs only
// stylistically; desktop d_ keys are minted where reuse would be a content regression
// (notably the compact export/danger button rows, whose labels are bare nouns against
// Android's phone-sized sentences). TrustLevel.displayName and RevocationReason's
// displayName/description stay untouched: DesktopBackupService matches displayName as a
// backup wire value, so the enum -> key mapping lives in this file instead (bottom).
// The "YYYY-MM-DD" token in the expiry label stays literal in every locale — the field is
// parsed with DateTimeFormatter.ofPattern("yyyy-MM-dd") and accepts nothing else.

package com.pgpony.desktop

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.awt.AwtWindow
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.data.TrustLevel
import kotlinx.coroutines.launch
import java.awt.FileDialog
import java.awt.Frame
import java.io.File
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
fun KeyDetailDialog(state: DesktopState, key: PGPKeyEntity, onDismiss: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    var subkeys by remember { mutableStateOf<List<DesktopKeyRepository.SubkeyInfo>>(emptyList()) }
    var saveTarget by remember { mutableStateOf<SaveTarget?>(null) }
    var showNotes by remember { mutableStateOf(false) }
    var showExpiration by remember { mutableStateOf(false) }
    var showRevoke by remember { mutableStateOf(false) }
    var showPublish by remember { mutableStateOf(false) }
    var showQr by remember { mutableStateOf(false) }

    LaunchedEffect(key.fingerprint, key.armoredPublicKey) {
        subkeys = state.repository.subkeyInfos(key.fingerprint)
    }

    BrandDialog(
        onDismissRequest = onDismiss,
        title = key.userID.ifBlank { tr("d_keydetail_no_user_id") },
        content = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 540.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    DetailPill(key.algorithm.displayName)
                    if (key.isKeyPair) {
                        Spacer(Modifier.width(6.dp))
                        DetailPill(tr("d_keydetail_badge_secret"), emphasized = true)
                    }
                    if (key.isDefault) {
                        Spacer(Modifier.width(6.dp))
                        DetailPill(tr("key_detail_badge_default"))
                    }
                    if (key.isCardBacked) {
                        Spacer(Modifier.width(6.dp))
                        DetailPill(tr("d_keydetail_badge_card"))
                    }
                    if (key.isRevoked) {
                        Spacer(Modifier.width(6.dp))
                        DetailPill(tr("key_detail_revoked_badge"), error = true)
                    }
                    if (key.isExpired) {
                        Spacer(Modifier.width(6.dp))
                        DetailPill(tr("d_keydetail_badge_expired"), error = true)
                    }
                }

                Spacer(Modifier.height(12.dp))
                Label(tr("key_detail_section_fingerprint"))
                Text(
                    key.formattedFingerprint,
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)
                )
                TextButton(onClick = {
                    clipboard.setText(AnnotatedString(key.fingerprint.uppercase()))
                    state.status = tr("d_keydetail_status_fingerprint_copied")
                }) { Text(tr("d_keydetail_copy_fingerprint")) }

                InfoLine(tr("d_keydetail_key_id"), key.longKeyId)
                InfoLine(tr("key_detail_detail_created"), dateOf(key.createdAt))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    InfoLine(
                        tr("key_detail_detail_expires"),
                        key.expiresAt?.let { dateOf(it) } ?: tr("key_detail_detail_expires_never")
                    )
                    if (key.isKeyPair && !key.isCardBacked && !key.isRevoked) {
                        TextButton(onClick = { showExpiration = true }) { Text(tr("d_common_edit_ellipsis")) }
                    }
                }

                // ── Trust (D2c) ─────────────────────────────────────────
                Spacer(Modifier.height(10.dp))
                Label(tr("key_detail_trust_level_label"))
                TrustLevel.entries.forEach { trust ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(
                            selected = key.trustLevel == trust,
                            onClick = { state.setTrust(key, trust) }
                        )
                        Text(trustName(trust), style = MaterialTheme.typography.bodyMedium)
                    }
                }

                // ── Notes (D2c) ─────────────────────────────────────────
                Spacer(Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Label(tr("key_detail_section_notes"))
                    TextButton(onClick = { showNotes = true }) {
                        Text(
                            if (key.notes.isNullOrBlank()) tr("d_common_add_ellipsis")
                            else tr("d_common_edit_ellipsis")
                        )
                    }
                }
                key.notes?.takeIf { it.isNotBlank() }?.let {
                    Text(it, style = MaterialTheme.typography.bodyMedium)
                }

                // ── Default signing key (D2c) ───────────────────────────
                if (key.isKeyPair && !key.isRevoked) {
                    Spacer(Modifier.height(6.dp))
                    if (!key.isDefault) {
                        TextButton(onClick = { state.makeDefault(key) }) {
                            Text(tr("d_keydetail_make_default_signing"))
                        }
                    }
                }

                Spacer(Modifier.height(12.dp))
                Label(tr("d_keydetail_section_keys", subkeys.size))
                subkeys.forEach { sk ->
                    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
                        Column(Modifier.padding(10.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    if (sk.isPrimary) tr("key_detail_userids_primary")
                                    else tr("d_keydetail_subkey"),
                                    style = MaterialTheme.typography.labelLarge
                                )
                                Spacer(Modifier.width(8.dp))
                                DetailPill(sk.algorithmLabel)
                            }
                            Text(
                                sk.keyIdHex.chunked(4).joinToString(" "),
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            val expiry = sk.expiresAtMs
                            Text(
                                if (expiry == null) {
                                    tr(
                                        "d_keydetail_subkey_meta",
                                        sk.capabilitiesLabel, dateOf(sk.createdAtMs)
                                    )
                                } else {
                                    tr(
                                        "d_keydetail_subkey_meta_expires",
                                        sk.capabilitiesLabel, dateOf(sk.createdAtMs), dateOf(expiry)
                                    )
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                Spacer(Modifier.height(14.dp))
                // D12 — this is the row the German build clipped: four buttons whose English
                // labels just fit, so "QR anzeigen…" was squeezed into a sliver and wrapped one
                // letter per line. WrapRow measures each button at its natural width and moves
                // the overflow onto a second line, which also retires the fixed 8.dp Spacers.
                WrapRow {
                    OutlinedButton(onClick = {
                        scope.launch {
                            val armor = state.repository.exportArmoredPublicKeyForSharing(key.fingerprint)
                            if (armor != null) {
                                clipboard.setText(AnnotatedString(armor))
                                state.status = tr("d_keydetail_status_pub_copied", key.shortFingerprint)
                            } else state.status = tr("d_keydetail_err_no_public_armor")
                        }
                    }) { Text(tr("d_keydetail_copy_public")) }
                    OutlinedButton(onClick = { saveTarget = SaveTarget.PUBLIC }) {
                        Text(tr("d_keydetail_export_public"))
                    }
                    OutlinedButton(onClick = { showQr = true }) { Text(tr("d_keydetail_show_qr")) }
                    if (key.isKeyPair) {
                        OutlinedButton(onClick = { saveTarget = SaveTarget.SECRET }) {
                            Text(tr("d_keydetail_export_secret"))
                        }
                    }
                }
                if (key.isKeyPair) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        tr("d_keydetail_secret_export_note"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                // ── Key servers (D4) ────────────────────────────────────
                Spacer(Modifier.height(14.dp))
                Label(tr("settings_section_keyservers"))
                InfoLine(
                    tr("key_detail_last_uploaded_label"),
                    key.lastUploadedAt?.let { dateOf(it) } ?: tr("key_detail_timestamp_never")
                )
                InfoLine(
                    tr("key_detail_last_checked_label"),
                    key.lastCheckedAt?.let { dateOf(it) } ?: tr("key_detail_timestamp_never")
                )
                Spacer(Modifier.height(4.dp))
                WrapRow {
                    OutlinedButton(
                        onClick = { state.refreshKeyFromServers(key) },
                        enabled = !state.busy
                    ) { Text(tr("d_keydetail_refresh_servers")) }
                    if (!key.isRevoked) {
                        OutlinedButton(
                            onClick = { showPublish = true },
                            enabled = !state.busy
                        ) { Text(tr("d_keyservers_publish")) }
                    }
                }

                // ── Danger zone (D2c) ───────────────────────────────────
                Spacer(Modifier.height(14.dp))
                Label(tr("d_keydetail_danger_zone"))
                Spacer(Modifier.height(4.dp))
                WrapRow {
                    if (key.isKeyPair && !key.isRevoked) {
                        OutlinedButton(onClick = { showRevoke = true }) {
                            Text(tr("key_detail_action_revoke_key"), color = MaterialTheme.colorScheme.error)
                        }
                    }
                    if (key.revocationCertificate != null) {
                        OutlinedButton(onClick = { saveTarget = SaveTarget.REVOCATION_CERT }) {
                            Text(tr("key_detail_action_export_revocation_cert"))
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(tr("common_button_close")) } }
    )

    if (showNotes) {
        NotesDialog(
            initial = key.notes.orEmpty(),
            onDismiss = { showNotes = false },
            onSave = { text ->
                showNotes = false
                state.setNotes(key, text.ifBlank { null })
            }
        )
    }

    if (showExpiration) {
        ExpirationDialog(
            current = key.expiresAt,
            onDismiss = { showExpiration = false },
            onSave = { epochSeconds, passphrase ->
                showExpiration = false
                state.setExpiration(key, epochSeconds, passphrase)
            }
        )
    }

    if (showPublish) {
        PublishKeyDialog(state, key) { showPublish = false }
    }

    if (showQr) {
        PublicKeyQrDialog(state, key) { showQr = false }
    }

    if (showRevoke) {
        RevokeDialog(
            key = key,
            busy = state.busy,
            onDismiss = { showRevoke = false },
            onRevoke = { reason, comment, passphrase ->
                state.revoke(key, reason, comment, passphrase) { showRevoke = false }
            }
        )
    }

    saveTarget?.let { target ->
        val suggested = when (target) {
            SaveTarget.PUBLIC -> "${key.shortFingerprint.lowercase()}-public.asc"
            SaveTarget.SECRET -> "${key.shortFingerprint.lowercase()}-SECRET.asc"
            SaveTarget.REVOCATION_CERT -> "${key.shortFingerprint.lowercase()}-revocation.asc"
        }
        SaveFileDialog(suggested) { file ->
            saveTarget = null
            if (file != null) scope.launch {
                val armor = when (target) {
                    SaveTarget.PUBLIC -> state.repository.exportArmoredPublicKeyForSharing(key.fingerprint)
                    SaveTarget.SECRET -> state.repository.exportArmoredPrivateKey(key.fingerprint)
                    SaveTarget.REVOCATION_CERT -> state.repository.exportRevocationCertificate(key.fingerprint)
                }
                if (armor != null) {
                    file.writeText(armor)
                    state.status = tr("d_keydetail_status_exported", file.name)
                } else state.status = tr("d_keydetail_status_nothing_to_export")
            }
        }
    }
}

private enum class SaveTarget { PUBLIC, SECRET, REVOCATION_CERT }

/**
 * D9 — render the public key as a QR for scan-to-import on another device. A large key
 * (RSA-4096) may exceed QR capacity; then we show the "share the .asc instead" message rather
 * than a broken image (the 4.1.0 §11 too-large posture). Offers to save the QR as a PNG.
 */
@Composable
private fun PublicKeyQrDialog(state: DesktopState, key: PGPKeyEntity, onDismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    var png by remember { mutableStateOf<ByteArray?>(null) }
    var tooLarge by remember { mutableStateOf(false) }
    var loading by remember { mutableStateOf(true) }
    var saveQr by remember { mutableStateOf(false) }

    LaunchedEffect(key.fingerprint) {
        val armor = state.repository.exportArmoredPublicKeyForSharing(key.fingerprint)
        if (armor == null) { loading = false; return@LaunchedEffect }
        val encoded = QrCode.encodeToPng(armor)
        png = encoded
        tooLarge = encoded == null
        loading = false
    }

    BrandDialog(
        onDismissRequest = onDismiss,
        title = tr("d_keydetail_qr_title"),
        content = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                val current = png
                when {
                    loading -> Text(tr("d_common_rendering"), style = MaterialTheme.typography.bodyMedium)
                    current != null -> {
                        val bitmap = remember(current) {
                            org.jetbrains.skia.Image.makeFromEncoded(current).toComposeImageBitmap()
                        }
                        Image(
                            bitmap = bitmap,
                            contentDescription = tr("exchange_qr_cd"),
                            modifier = Modifier.size(320.dp)
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            tr("d_keydetail_qr_hint", key.userID.ifBlank { key.shortFingerprint }),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    tooLarge -> Text(
                        tr("d_keydetail_qr_too_large"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error
                    )
                    else -> Text(
                        tr("d_keydetail_qr_no_material"),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        },
        confirmButton = {
            if (png != null) TextButton(onClick = { saveQr = true }) { Text(tr("d_keydetail_qr_save_png")) }
            else TextButton(onClick = onDismiss) { Text(tr("common_button_close")) }
        },
        dismissButton = { if (png != null) TextButton(onClick = onDismiss) { Text(tr("common_button_close")) } }
    )

    if (saveQr) {
        SaveFileDialog("${key.shortFingerprint.lowercase()}-qr.png") { file ->
            saveQr = false
            val bytes = png
            if (file != null && bytes != null) scope.launch {
                file.writeBytes(bytes)
                state.status = tr("d_keydetail_status_qr_saved", file.name)
            }
        }
    }
}

// ── Mutation sub-dialogs ───────────────────────────────────────────────

@Composable
private fun NotesDialog(initial: String, onDismiss: () -> Unit, onSave: (String) -> Unit) {
    var text by remember { mutableStateOf(initial) }
    BrandDialog(
        onDismissRequest = onDismiss,
        title = tr("key_detail_section_notes"),
        content = {
            OutlinedTextField(
                value = text, onValueChange = { text = it },
                modifier = Modifier.fillMaxWidth().height(140.dp)
            )
        },
        confirmButton = { TextButton(onClick = { onSave(text) }) { Text(tr("common_button_save")) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("common_button_cancel")) } }
    )
}

@Composable
private fun ExpirationDialog(
    current: Long?,
    onDismiss: () -> Unit,
    onSave: (epochSeconds: Long?, passphrase: String?) -> Unit
) {
    var never by remember { mutableStateOf(current == null) }
    var dateText by remember {
        mutableStateOf(
            current?.let { DATE_FORMAT.format(Instant.ofEpochMilli(it).atZone(ZoneId.systemDefault())) }
                ?: DATE_FORMAT.format(LocalDate.now().plusYears(2))
        )
    }
    var passphrase by remember { mutableStateOf("") }
    val parsedDate = runCatching { LocalDate.parse(dateText, DATE_FORMAT) }.getOrNull()
    val valid = never || (parsedDate != null && parsedDate.isAfter(LocalDate.now()))

    BrandDialog(
        onDismissRequest = onDismiss,
        title = tr("key_detail_expiry_sheet_title"),
        content = {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = never, onCheckedChange = { never = it })
                    Text(tr("d_keydetail_expiry_never"))
                }
                if (!never) {
                    OutlinedTextField(
                        value = dateText, onValueChange = { dateText = it },
                        label = { Text(tr("d_keydetail_expiry_date_label")) }, singleLine = true,
                        isError = parsedDate == null || !parsedDate.isAfter(LocalDate.now()),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = passphrase, onValueChange = { passphrase = it },
                    label = { Text(tr("key_detail_expiry_passphrase_label")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    tr("d_keydetail_expiry_note"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = valid,
                onClick = {
                    val epochSeconds = if (never) null
                    else parsedDate!!.atStartOfDay(ZoneId.systemDefault()).toEpochSecond()
                    onSave(epochSeconds, passphrase.ifBlank { null })
                }
            ) { Text(tr("common_button_save")) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("common_button_cancel")) } }
    )
}

@Composable
private fun RevokeDialog(
    key: PGPKeyEntity,
    busy: Boolean,
    onDismiss: () -> Unit,
    onRevoke: (RevocationReason, String?, String?) -> Unit
) {
    var reason by remember { mutableStateOf(RevocationReason.NO_REASON) }
    var comment by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }
    var confirmed by remember { mutableStateOf(false) }

    BrandDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = tr("d_keydetail_revoke_title", key.userID.ifBlank { key.shortFingerprint }),
        destructive = true,
        content = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 460.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    tr("d_keydetail_revoke_warning"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(Modifier.height(8.dp))
                RevocationReason.entries.forEach { r ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = reason == r, onClick = { reason = r }, enabled = !busy)
                        Column {
                            Text(reasonName(r), style = MaterialTheme.typography.bodyMedium)
                            Text(
                                reasonDescription(r),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = comment, onValueChange = { comment = it },
                    label = { Text(tr("revoke_sheet_comment_label")) }, singleLine = true,
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = passphrase, onValueChange = { passphrase = it },
                    label = { Text(tr("key_detail_expiry_passphrase_label")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = confirmed, onCheckedChange = { confirmed = it }, enabled = !busy)
                    Text(tr("d_keydetail_revoke_ack"))
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = confirmed && !busy,
                onClick = { onRevoke(reason, comment.ifBlank { null }, passphrase.ifBlank { null }) }
            ) {
                Text(
                    if (busy) tr("d_common_working") else tr("revoke_sheet_confirm"),
                    color = MaterialTheme.colorScheme.error
                )
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text(tr("common_button_cancel")) } }
    )
}

// ── Shared bits ────────────────────────────────────────────────────────

@Composable
private fun Label(text: String) =
    Text(text, style = MaterialTheme.typography.titleSmall)

@Composable
private fun InfoLine(label: String, value: String) {
    Row {
        Text("$label:", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.width(6.dp))
        Text(value, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun DetailPill(text: String, emphasized: Boolean = false, error: Boolean = false) {
    Surface(
        shape = MaterialTheme.shapes.small,
        color = when {
            error -> MaterialTheme.colorScheme.error
            emphasized -> MaterialTheme.colorScheme.primary
            else -> MaterialTheme.colorScheme.surfaceVariant
        }
    ) {
        Text(
            text,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
            style = MaterialTheme.typography.labelSmall,
            color = if (error || emphasized) MaterialTheme.colorScheme.onPrimary
            else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

/** Native save dialog (AWT FileDialog, SAVE mode) — same AwtWindow pattern as the picker. */
@Composable
private fun SaveFileDialog(suggestedName: String, onResult: (File?) -> Unit) {
    // Read in composable scope: the AwtWindow create lambda runs off-composition, so a
    // tr() call inside it would not resubscribe when the language changes.
    val title = tr("d_keydetail_save_dialog_title")
    AwtWindow(
        create = {
            object : FileDialog(null as Frame?, title, SAVE) {
                init { file = suggestedName }
                override fun setVisible(visible: Boolean) {
                    super.setVisible(visible)
                    if (visible) {
                        onResult(file?.let { File(directory, it) })
                    }
                }
            }
        },
        dispose = FileDialog::dispose
    )
}

private val DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd")
private fun dateOf(epochMs: Long): String =
    DATE_FORMAT.format(Instant.ofEpochMilli(epochMs).atZone(ZoneId.systemDefault()))

// ── Vendored enum -> string key mapping ────────────────────────────────
//
// TrustLevel.displayName is a BACKUP WIRE VALUE (DesktopBackupService matches on it), and
// RevocationReason's displayName/description live in vendored source that must never be
// hand-edited. So the localization happens here, at the UI boundary. Each branch spells out a
// complete tr() call with an inline string literal — never a returned key name — so I18nTest's
// source scan covers all fourteen inherited Android keys.

// Not private: Gui.kt's status line needs the same enum -> key mapping (a status message
// must not leak the backup wire value either).
internal fun trustName(trust: TrustLevel): String = when (trust) {
    TrustLevel.UNKNOWN -> tr("trust_level_unknown_name")
    TrustLevel.UNVERIFIED -> tr("trust_level_unverified_name")
    TrustLevel.VERIFIED -> tr("trust_level_verified_name")
    TrustLevel.ULTIMATE -> tr("trust_level_ultimate_name")
}

internal fun reasonName(reason: RevocationReason): String = when (reason) {
    RevocationReason.NO_REASON -> tr("revocation_reason_no_reason_name")
    RevocationReason.SUPERSEDED -> tr("revocation_reason_superseded_name")
    RevocationReason.COMPROMISED -> tr("revocation_reason_compromised_name")
    RevocationReason.RETIRED -> tr("revocation_reason_retired_name")
    RevocationReason.USER_ID_INVALID -> tr("revocation_reason_user_id_invalid_name")
}

private fun reasonDescription(reason: RevocationReason): String = when (reason) {
    RevocationReason.NO_REASON -> tr("revocation_reason_no_reason_description")
    RevocationReason.SUPERSEDED -> tr("revocation_reason_superseded_description")
    RevocationReason.COMPROMISED -> tr("revocation_reason_compromised_description")
    RevocationReason.RETIRED -> tr("revocation_reason_retired_description")
    RevocationReason.USER_ID_INVALID -> tr("revocation_reason_user_id_invalid_description")
}
