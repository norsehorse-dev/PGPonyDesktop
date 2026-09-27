// KeyringScreen.kt
// PGPony Desktop — D2a keyring: Room-backed rows (the vendored PGPKeyEntity, so fingerprint
// formatting / v6 key-ID handling / expiry all come from the same code Android ships), import
// from file or pasted armor, copy-public-to-clipboard, delete with confirmation. Key detail,
// keygen, and full export flows are D2b.
//
// D11b — localized. SortMode carries KEY NAMES, not labels: an enum entry is a compile-time
// constant, so it cannot hold a translated string (the Destination pattern in Gui.kt). The two
// AWT file pickers take their title as a parameter because the create = { } lambda runs
// outside composition. The armor header in the paste placeholder is protocol framing, not
// copy, and stays in English.

package com.pgpony.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.awt.AwtWindow
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.launch
import java.awt.FileDialog
import java.awt.Frame
import java.io.File
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
fun KeyringScreen(state: DesktopState) {
    var showFilePicker by remember { mutableStateOf(false) }
    var showPasteDialog by remember { mutableStateOf(false) }
    var showGenerate by remember { mutableStateOf(false) }
    var showServerSearch by remember { mutableStateOf(false) }
    var showQrImport by remember { mutableStateOf(false) }
    var detailKey by remember { mutableStateOf<PGPKeyEntity?>(null) }
    var confirmDelete by remember { mutableStateOf<PGPKeyEntity?>(null) }
    var showRecentlyDeleted by remember { mutableStateOf(false) }
    var publishNewKey by remember { mutableStateOf<PGPKeyEntity?>(null) }
    var sameIdentityEmail by remember { mutableStateOf<String?>(null) }
    val sameIdentityCounts = remember(state.keys) {
        state.keys.filter { it.userEmail.isNotBlank() }
            .groupingBy { it.userEmail.trim().lowercase() }.eachCount()
    }
    var query by remember { mutableStateOf("") }
    var sortMode by remember { mutableStateOf(SortMode.RECENT) }
    var sortMenuOpen by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()

    // D9 — the menu bar's "New key…" opens the generator here.
    androidx.compose.runtime.LaunchedEffect(state.uiRequest) {
        if (state.uiRequest == UiRequest.NEW_KEY) { showGenerate = true; state.consumeUiRequest() }
    }

    // D2c — client-side search + sort over the Room rows. Manual drag-reorder (the Android
    // MANUAL sort mode) is deferred until the reorderable dependency is proven on desktop.
    val displayKeys = remember(state.keys, query, sortMode) {
        val q = query.trim()
        val filtered = if (q.isBlank()) state.keys else state.keys.filter { k ->
            k.userID.contains(q, ignoreCase = true) ||
                k.userEmail.contains(q, ignoreCase = true) ||
                k.fingerprint.contains(q.replace(" ", ""), ignoreCase = true)
        }
        when (sortMode) {
            SortMode.RECENT -> filtered            // DAO order: createdAt DESC
            SortMode.NAME -> filtered.sortedBy { it.userName.lowercase().ifBlank { it.userEmail } }
            SortMode.ALGORITHM -> filtered.sortedBy { it.algorithm.displayName }
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(Spacing.Section)) {

        // D12 batch 2 — the shared masthead. The weighted-spacer-plus-WrapRow arrangement that
        // batch 1 worked out here now lives inside ScreenHeader, so every screen inherits it:
        // while the five labels fit, the spacer pushes them to the right edge; in German and
        // Japanese, where they don't, the WrapRow claims the remaining width, the spacer
        // collapses, and the group takes a second line instead of the last button being crushed.
        ScreenHeader(
            title = tr("keyring_title"),
            subtitle = trQuantity("d_keyring_key_count", state.keys.size)
        ) {
            OutlinedButton(onClick = { showServerSearch = true }) { Text(tr("d_keyring_search_servers")) }
            OutlinedButton(onClick = { showPasteDialog = true }) { Text(tr("d_keyring_paste_armor")) }
            OutlinedButton(onClick = { showFilePicker = true }) { Text(tr("d_keyring_import_file")) }
            OutlinedButton(onClick = { showQrImport = true }) { Text(tr("d_keyring_import_qr")) }
            if (state.deletedKeys.isNotEmpty()) {
                OutlinedButton(onClick = { showRecentlyDeleted = true }) {
                    Text(tr("d_keyring_recently_deleted_button", state.deletedKeys.size))
                }
            }
            BrandButton(onClick = { showGenerate = true }) { Text(tr("d_menu_new_key")) }
        }

        Spacer(Modifier.height(Spacing.Large))
        WrapRow(horizontalSpacing = Spacing.Medium, verticalSpacing = Spacing.Small) {
            OutlinedTextField(
                value = query, onValueChange = { query = it },
                placeholder = { Text(tr("d_keyring_search_placeholder")) },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
                shape = RoundedCornerShape(Radius.Small),
                modifier = Modifier.width(340.dp)
            )
            // The sort button and its menu are boxed together: WrapRow packs every direct child
            // as its own item, and a DropdownMenu measures to nothing, so a bare popup sibling
            // would consume a slot and desynchronise the gaps (batch 1, PassScreen).
            Box {
                OutlinedButton(
                    onClick = { sortMenuOpen = true },
                    shape = RoundedCornerShape(Radius.Small)
                ) {
                    Text(tr("d_keyring_sort_label", tr(sortMode.labelKey)))
                }
                DropdownMenu(expanded = sortMenuOpen, onDismissRequest = { sortMenuOpen = false }) {
                    SortMode.entries.forEach { mode ->
                        DropdownMenuItem(
                            text = { Text(tr(mode.labelKey)) },
                            onClick = { sortMode = mode; sortMenuOpen = false }
                        )
                    }
                }
            }
            if (query.isNotBlank()) {
                Text(
                    trQuantity("d_keyring_match_count", displayKeys.size),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        state.status?.let {
            Spacer(Modifier.height(Spacing.Medium))
            StatusStrip(it)
        }

        Spacer(Modifier.height(Spacing.Large))

        when {
            // fillMaxSize here, not inside EmptyState: this column has a bounded height, so the
            // state can be centred in whatever the list would have occupied. The scrolling
            // screens can't do that and pass nothing.
            state.keys.isEmpty() -> EmptyState(
                icon = Icons.Filled.VpnKey,
                title = tr("d_keyring_empty_title"),
                message = tr("d_keyring_empty_body"),
                modifier = Modifier.fillMaxSize()
            ) {
                BrandButton(onClick = { showGenerate = true }) { Text(tr("d_menu_new_key")) }
                OutlinedButton(onClick = { showFilePicker = true }) { Text(tr("d_keyring_import_file")) }
            }

            // Before D12 a search that matched nothing showed an empty list and no explanation,
            // which is indistinguishable from an empty keyring. The query is echoed back because
            // the usual cause is a typo in it.
            displayKeys.isEmpty() -> EmptyState(
                icon = Icons.Filled.Search,
                title = tr("d_keyring_no_matches_title"),
                message = tr("d_keyring_no_matches_body", query.trim()),
                modifier = Modifier.fillMaxSize()
            ) {
                OutlinedButton(onClick = { query = "" }) { Text(tr("d_keyring_clear_search")) }
            }

            else -> LazyColumn(verticalArrangement = Arrangement.spacedBy(Spacing.Medium)) {
                items(displayKeys, key = { it.id }) { key ->
                    KeyCard(
                        key = key,
                        // 3.0.0 (Android 4.6.0 item 20): how many keys share this address.
                        sameIdentity = sameIdentityCounts[key.userEmail.trim().lowercase()] ?: 1,
                        onSameIdentity = { sameIdentityEmail = key.userEmail },
                        onOpen = { detailKey = key },
                        onCopyPublic = {
                            scope.launch {
                                val armor = state.publicArmorFor(key)
                                if (armor != null) {
                                    clipboard.setText(AnnotatedString(armor))
                                    state.status =
                                        tr("d_keydetail_status_pub_copied", key.shortFingerprint)
                                } else {
                                    state.status =
                                        tr("d_keyring_err_no_public_armor_for", key.shortFingerprint)
                                }
                            }
                        },
                        onDelete = { confirmDelete = key }
                    )
                }
            }
        }
    }

    val keyFileDialogTitle = tr("d_keyring_import_file_dialog")
    if (showFilePicker) {
        KeyFileDialog(keyFileDialogTitle) { file ->
            showFilePicker = false
            file?.let { state.importBytes(it.readBytes()) }
        }
    }

    if (showPasteDialog) {
        PasteArmorDialog(
            onDismiss = { showPasteDialog = false },
            onImport = { text ->
                showPasteDialog = false
                state.importArmoredText(text)
            }
        )
    }

    if (showServerSearch) {
        SearchKeyServersDialog(state) { showServerSearch = false }
    }

    val qrDialogTitle = tr("d_keyring_qr_dialog")
    if (showQrImport) {
        // Pick an image file (screenshot/photo export) and decode a key QR out of it.
        QrImageDialog(qrDialogTitle) { file ->
            showQrImport = false
            if (file != null) {
                val decoded = QrCode.decodeFromImage(file)
                when {
                    decoded == null ->
                        state.status = tr("d_keyring_qr_none_found", file.name)
                    decoded.contains("-----BEGIN PGP") ->
                        state.importArmoredText(decoded)
                    else ->
                        state.status = tr("d_keyring_qr_not_a_key")
                }
            }
        }
    }

    if (showGenerate) {
        GenerateKeyDialog(
            busy = state.busy,
            onDismiss = { showGenerate = false },
            onGenerate = { request ->
                state.generate(request) { entity ->
                    showGenerate = false
                    // Android 4.5.0 item 8: offer to publish, online only, and only a key with an
                    // address (key servers find keys by email).
                    if (KeygenPrefs.offerPublish() && !com.pgpony.android.network.OfflineMode.enabled &&
                        entity.userEmail.isNotBlank()
                    ) publishNewKey = entity
                }
            }
        )
    }

    publishNewKey?.let { key ->
        PublishKeyDialog(state, key) { publishNewKey = null }
    }

    detailKey?.let { key ->
        // Re-resolve from state so the dialog reflects the freshest row.
        val fresh = state.keys.firstOrNull { it.id == key.id } ?: key
        KeyDetailDialog(state = state, key = fresh, onDismiss = { detailKey = null })
    }

    if (showRecentlyDeleted) RecentlyDeletedDialog(state) { showRecentlyDeleted = false }

    sameIdentityEmail?.let { email ->
        val matches = state.keys.filter { it.userEmail.trim().equals(email.trim(), ignoreCase = true) }
        BrandDialog(
            onDismissRequest = { sameIdentityEmail = null },
            title = trQuantity("keyring_same_identity_title", matches.size, email),
            content = {
                Column {
                    Text(tr("keyring_same_identity_body"))
                    Spacer(Modifier.height(Spacing.Medium))
                    matches.forEach { k ->
                        TextButton(onClick = { sameIdentityEmail = null; detailKey = k }) {
                            Column {
                                Text(k.userID.ifBlank { k.shortFingerprint })
                                Text(
                                    k.formattedFingerprint + tr("d_list_separator") + tr(
                                        "keyring_same_identity_created_format",
                                        DATE_FORMAT.format(Instant.ofEpochMilli(k.createdAt).atZone(ZoneId.systemDefault()))
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { sameIdentityEmail = null }) { Text(tr("common_button_close")) } }
        )
    }

    confirmDelete?.let { key ->
        // 3.0.0 (plan 3.1 / 3.2): delete moves the key to Recently Deleted. A key pair gets the
        // Android safeguards: the backup state, and "revoke instead", since a revocation
        // certificate cannot be made once the key is gone. The typed word applies when
        // Protect destructive actions is on.
        val body = if (key.isKeyPair) tr("key_delete_sheet_body", DesktopKeyEdits.RETENTION_DAYS)
        else tr(
            "keyring_delete_dialog_body_format",
            key.userID.ifBlank { tr("d_keydetail_no_user_id") }, key.shortFingerprint, DesktopKeyEdits.RETENTION_DAYS
        )
        DestructiveConfirmDialog(
            title = if (key.isKeyPair) tr("key_delete_sheet_title") else tr("keyring_delete_dialog_title"),
            body = (if (key.isKeyPair) key.userID.ifBlank { key.shortFingerprint } + "\n\n" else "") + body,
            confirmLabel = if (key.isKeyPair) tr("key_delete_confirm_button") else tr("keyring_delete_dialog_confirm"),
            onConfirm = { state.delete(key); confirmDelete = null },
            onDismiss = { confirmDelete = null },
            extra = {
                if (key.isKeyPair) {
                    Spacer(Modifier.height(Spacing.Small))
                    Text(
                        key.lastBackedUpAt?.let {
                            tr("key_delete_backed_up_on", DATE_FORMAT.format(Instant.ofEpochMilli(it).atZone(ZoneId.systemDefault())))
                        } ?: tr("key_delete_never_backed_up"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (!key.isRevoked) {
                        Spacer(Modifier.height(Spacing.Small))
                        Text(tr("key_delete_revoke_instead_note"), style = MaterialTheme.typography.bodySmall)
                        TextButton(onClick = { confirmDelete = null; detailKey = key }) {
                            Text(tr("key_delete_revoke_instead_button"))
                        }
                    }
                }
            }
        )
    }
}

/**
 * One row of the keyring.
 *
 * D12 — the badges and the title share a [WrapRow] rather than a bare `Row`. A key whose user ID
 * is a long name plus a long address used to push its own badges off the right edge; now the
 * badge group drops to a second line and stays readable. The avatar tile on the left is the one
 * place the gradient appears in the list: filled for a key pair, washed for a public key, which
 * makes "do I hold the secret half" answerable without reading a word.
 */
@Composable
private fun KeyCard(
    key: PGPKeyEntity,
    sameIdentity: Int,
    onSameIdentity: () -> Unit,
    onOpen: () -> Unit,
    onCopyPublic: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        shape = RoundedCornerShape(Radius.Medium),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        modifier = Modifier.fillMaxWidth().clickable(onClick = onOpen)
    ) {
        Row(modifier = Modifier.padding(Spacing.Large)) {
            KeyAvatar(isKeyPair = key.isKeyPair)
            Spacer(Modifier.width(Spacing.Medium))
            Column(Modifier.weight(1f)) {
                WrapRow(horizontalSpacing = Spacing.Small, verticalSpacing = Spacing.Tight) {
                    Text(
                        key.userID.ifBlank { tr("d_keydetail_no_user_id") },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    BrandBadge(key.algorithm.displayName)
                    if (key.isKeyPair) BrandBadge(tr("d_keydetail_badge_secret"), BadgeTone.Brand)
                    // 1.1.0 — field report: card-backed rows were only identifiable by opening
                    // the detail dialog. Same key the dialog renders, already in all six locales.
                    if (key.isCardBacked) BrandBadge(tr("d_keydetail_badge_card"), BadgeTone.Brand)
                    if (key.isDefault) BrandBadge(tr("key_detail_badge_default"))
                    if (key.isRevoked) BrandBadge(tr("key_card_revoked_badge"), BadgeTone.Error)
                    if (key.isExpired) BrandBadge(tr("d_keydetail_badge_expired"), BadgeTone.Error)
                    if (sameIdentity > 1) {
                        Box(Modifier.clickable(onClick = onSameIdentity)) {
                            BrandBadge(trQuantity("key_card_same_identity_count", sameIdentity))
                        }
                    }
                }
                // 3.0.0 (Android 4.6.0 item 1): the key's note as a label on its row.
                key.notes?.takeIf { it.isNotBlank() }?.let { note ->
                    Spacer(Modifier.height(Spacing.Tight))
                    Text(
                        note.lineSequence().first().take(120),
                        style = MaterialTheme.typography.bodySmall,
                        color = Brand.Accent
                    )
                }
                Spacer(Modifier.height(Spacing.Small))
                Text(
                    key.formattedFingerprint,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(Spacing.Tight))
                val created = DATE_FORMAT.format(Instant.ofEpochMilli(key.createdAt).atZone(ZoneId.systemDefault()))
                val expires = key.expiresAt?.let {
                    tr(
                        "d_keyring_meta_expires",
                        DATE_FORMAT.format(Instant.ofEpochMilli(it).atZone(ZoneId.systemDefault()))
                    )
                } ?: ""
                Text(
                    tr("d_keyring_meta_line", created, expires, key.longKeyId),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Row {
                IconButton(onClick = onCopyPublic) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = tr("d_keyring_cd_copy_public"))
                }
                // 3.0.0 (plan 3.2): Hide destructive actions removes delete from the app.
                if (!DestructiveGuard.hidden()) {
                    IconButton(onClick = onDelete) {
                        Icon(Icons.Filled.Delete, contentDescription = tr("d_keyring_cd_delete"))
                    }
                }
            }
        }
    }
}

/** The 44dp brand tile at the head of a [KeyCard]. Filled for a key pair, washed for a public key. */
@Composable
private fun KeyAvatar(isKeyPair: Boolean) {
    Box(
        Modifier
            .size(44.dp)
            .clip(RoundedCornerShape(Radius.Medium))
            .background(if (isKeyPair) Brand.gradient() else Brand.gradientWash(0.18f)),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            Icons.Filled.VpnKey,
            contentDescription = null,
            tint = if (isKeyPair) Color.White else Brand.Accent,
            modifier = Modifier.size(22.dp)
        )
    }
}

/** Native file picker (AWT FileDialog) — the JetBrains-documented AwtWindow pattern. */
@Composable
private fun KeyFileDialog(title: String, onResult: (File?) -> Unit) = AwtWindow(
    create = {
        object : FileDialog(null as Frame?, title, LOAD) {
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

/** D9 — image picker for QR import (a screenshot/photo containing a key QR). */
@Composable
private fun QrImageDialog(title: String, onResult: (File?) -> Unit) = AwtWindow(
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

@Composable
private fun PasteArmorDialog(onDismiss: () -> Unit, onImport: (String) -> Unit) {
    var text by remember { mutableStateOf("") }
    BrandDialog(
        onDismissRequest = onDismiss,
        title = tr("import_paste_label"),
        content = {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                modifier = Modifier.fillMaxWidth().height(220.dp),
                placeholder = { Text("-----BEGIN PGP PUBLIC KEY BLOCK-----") }
            )
        },
        confirmButton = {
            TextButton(onClick = { onImport(text) }, enabled = text.contains("-----BEGIN PGP")) {
                Text(tr("d_common_import"))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("common_button_cancel")) } }
    )
}

/** D2c sort modes — the Android SortMode set minus MANUAL (drag-reorder deferred). */
enum class SortMode(val labelKey: String) {
    RECENT("d_keyring_sort_recent"),
    NAME("d_keyring_sort_name"),
    ALGORITHM("d_keyring_sort_algorithm")
}

private val DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd")
