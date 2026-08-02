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
            onGenerate = { name, email, algorithm, passphrase ->
                state.generate(name, email, algorithm, passphrase) { showGenerate = false }
            }
        )
    }

    detailKey?.let { key ->
        // Re-resolve from state so the dialog reflects the freshest row.
        val fresh = state.keys.firstOrNull { it.id == key.id } ?: key
        KeyDetailDialog(state = state, key = fresh, onDismiss = { detailKey = null })
    }

    confirmDelete?.let { key ->
        BrandDialog(
            onDismissRequest = { confirmDelete = null },
            title = tr("keyring_delete_dialog_title"),
            destructive = true,
            content = {
                Text(
                    buildString {
                        append(key.userID.ifBlank { tr("d_keydetail_no_user_id") })
                        append("\n")
                        append(key.formattedFingerprint)
                        if (key.isKeyPair) append(tr("d_keyring_delete_secret_warning"))
                    }
                )
            },
            confirmButton = {
                TextButton(onClick = { state.delete(key); confirmDelete = null }) {
                    Text(tr("keyring_delete_dialog_confirm"))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = null }) { Text(tr("common_button_cancel")) }
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
                IconButton(onClick = onDelete) {
                    Icon(Icons.Filled.Delete, contentDescription = tr("d_keyring_cd_delete"))
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
