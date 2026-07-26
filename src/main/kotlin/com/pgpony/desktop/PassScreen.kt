// PassScreen.kt
// PGPony Desktop — D8: the read-only `pass` (password-store) surface. Parity target is the
// Android trio (PassStoreListScreen / PassBrowserScreen / PassEntryScreen) collapsed into one
// two-pane desktop window: stores across the top, the tree on the left, the selected entry on
// the right.
//
// The entry pane runs the SAME state machine as Android's PassEntryScreen —
//   Locked → Working → (PassphraseNeeded | CardNeeded | CardWaiting) → Shown | Failed
// — with two desktop substitutions:
//   * Android gates the screen behind biometrics; the desktop has no equivalent it can rely on
//     across three OSes, so the gate becomes an AUTO-RELOCK: decrypted content is dropped after
//     RELOCK_SECONDS of sitting on screen, and on every selection change.
//   * The card path goes through D7's CardOpDialog (PC/SC, PW1, touch) instead of the NFC tap.
//
// Read-only, like Android 3.0: nothing here writes to the store. Decryption is lazy and one
// entry at a time — browsing never decrypts.
//
// TOTP is LIVE, from the shared core. D8 adds `crypto/pass/PassTotp.kt` upstream in
// PGPonyAndroid — RFC 6238 written once, vendored here, RFC 6238 Appendix B vectors in the
// vendored test suite — so an `otpauth://` line becomes a rolling code with a countdown instead
// of a URI and an apology. Android 4.1.0 §7 wires the same object into PassEntryScreen; the
// generator is not written twice. The URI itself stays hidden behind a toggle (it carries the
// TOTP secret) but is still copyable, for moving the entry to another authenticator.
//
// D11b — LOCALIZATION. Android already ships this surface as three screens
// (PassStoreListScreen / PassBrowserScreen / PassEntryScreen), so seventeen strings here are
// ANDROID keys reused verbatim — pass_entry_passphrase_hint, pass_entry_unlock,
// pass_entry_notes_label, provider_cardop_waiting and the rest — and arrive already translated
// into five languages. A `d_pass_*` key is minted only where the desktop says something the phone
// doesn't: the store bar (Android gives that its own screen), the auto-relock note that stands in
// for the biometric gate, the search-hit count, and the whole live-TOTP block, which on Android
// is still the "code generation is not supported" apology.

package com.pgpony.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.awt.AwtWindow
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.crypto.pass.PassDecryptCoordinator
import com.pgpony.android.crypto.pass.PassEntryContent
import com.pgpony.android.crypto.pass.PassEntryParser
import com.pgpony.android.crypto.pass.PassNode
import com.pgpony.android.crypto.pass.PassRoute
import com.pgpony.android.crypto.pass.PassStorePrefs
import com.pgpony.android.crypto.pass.PassStoreRef
import com.pgpony.android.crypto.pass.PassTotp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.FileDialog
import java.awt.Frame
import java.io.File
import javax.swing.JFileChooser
import javax.swing.SwingUtilities

/** Decrypted content is dropped after this long on screen (the biometric-gate stand-in). */
private const val RELOCK_SECONDS = 120

/** The entry pane's state machine — the Android PassEntryScreen states, name for name. */
private sealed interface EntryState {
    data object Locked : EntryState
    data object Working : EntryState
    data class PassphraseNeeded(val retry: Boolean) : EntryState
    data object CardNeeded : EntryState
    data object CardWaiting : EntryState
    data class Shown(val content: PassEntryContent) : EntryState
    data class Failed(val message: String) : EntryState
}

@Composable
fun PassScreen(state: DesktopState) {
    val scope = rememberCoroutineScope()

    var stores by remember { mutableStateOf(PassStorePrefs.load()) }
    var selectedStore by remember { mutableStateOf(stores.lastOrNull()) }
    var tree by remember { mutableStateOf<PassNode.Folder?>(null) }
    var folderPath by remember { mutableStateOf("") }
    var query by remember { mutableStateOf("") }
    var selectedEntry by remember { mutableStateOf<PassNode.Entry?>(null) }
    var showPicker by remember { mutableStateOf(false) }
    var storeMenu by remember { mutableStateOf(false) }
    var walkError by remember { mutableStateOf<String?>(null) }
    var walkTick by remember { mutableStateOf(0) }

    // The walk is filesystem IO over a whole tree — off the composition thread. Re-runs when
    // the selected store changes or Rescan is pressed (the store is read in place, so a `git
    // pull` or a Syncthing sync can change it under us).
    LaunchedEffect(selectedStore?.id, walkTick) {
        folderPath = ""
        selectedEntry = null
        val ref = selectedStore
        if (ref == null) {
            tree = null
            walkError = null
            return@LaunchedEffect
        }
        val walked = withContext(Dispatchers.IO) { DesktopPassStore.walkTree(ref) }
        tree = walked
        walkError = if (walked == null)
            tr("d_pass_store_unreadable", DesktopPassStore.pathOf(ref.treeUri) ?: ref.treeUri)
        else null
    }

    fun addStore(dir: File) {
        val path = dir.toPath()
        if (!DesktopPassStore.looksLikeStore(path)) {
            state.status = tr("d_pass_not_a_store", path)
            return
        }
        val ref = DesktopPassStore.buildRef(path)
        stores = PassStorePrefs.upsert(ref)
        selectedStore = stores.lastOrNull { it.treeUri == ref.treeUri } ?: ref
        state.status = tr("d_pass_store_added", ref.displayName)
    }

    Column(modifier = Modifier.fillMaxSize().padding(Spacing.Section)) {

        // ── Store bar ───────────────────────────────────────────────────
        //
        // D12 — the store controls are the screen header's action group now. ScreenHeader owns
        // the weighted-spacer-plus-WrapRow arrangement, so the same five controls that used to
        // share a WrapRow with the title still wrap as a group in German and Japanese.
        ScreenHeader(title = tr("d_pass_store_title")) {
            if (stores.isNotEmpty()) {
                // The menu is wrapped with its anchor rather than left as a sibling. Under
                // WrapRow every direct child is packed as its own item, and a DropdownMenu is a
                // popup that measures to nothing, so on its own it would consume a slot and
                // desynchronise the gaps. Boxed with the button it stays one item, and it also
                // keeps anchoring to the control it belongs to.
                Box {
                    OutlinedButton(
                        onClick = { storeMenu = true },
                        shape = RoundedCornerShape(Radius.Small)
                    ) {
                        Text(selectedStore?.displayName ?: tr("d_pass_choose_store"))
                    }
                    DropdownMenu(expanded = storeMenu, onDismissRequest = { storeMenu = false }) {
                        stores.forEach { ref ->
                            DropdownMenuItem(
                                text = { Text(ref.displayName) },
                                onClick = { selectedStore = ref; storeMenu = false }
                            )
                        }
                    }
                }
            }
            OutlinedButton(
                onClick = { showPicker = true },
                shape = RoundedCornerShape(Radius.Small)
            ) { Text(tr("d_pass_add_store")) }
            // Offer the conventional location as a one-click add, but only while it exists and
            // isn't already on the list. Compared absolute+normalized: treeUri round-trips
            // through a file: URI, so a raw Path comparison would miss the match.
            val defaultPath = remember { DesktopPassStore.defaultStorePath().toAbsolutePath().normalize() }
            val offerDefault = remember(stores) {
                DesktopPassStore.looksLikeStore(defaultPath) &&
                    stores.none {
                        DesktopPassStore.pathOf(it.treeUri)?.toAbsolutePath()?.normalize() == defaultPath
                    }
            }
            if (offerDefault) {
                OutlinedButton(
                    onClick = { addStore(defaultPath.toFile()) },
                    shape = RoundedCornerShape(Radius.Small)
                ) {
                    Text(tr("d_pass_use_default"))
                }
            }
            if (selectedStore != null) {
                TextButton(onClick = { walkTick++ }) { Text(tr("d_pass_rescan")) }
            }
            selectedStore?.let { ref ->
                TextButton(onClick = {
                    stores = PassStorePrefs.remove(ref.id)
                    selectedStore = stores.lastOrNull()
                    state.status = tr("d_pass_store_removed", ref.displayName)
                }) { Text(tr("pass_store_remove_confirm")) }
            }
        }

        selectedStore?.let { ref ->
            Spacer(Modifier.height(Spacing.Small))
            Text(
                DesktopPassStore.pathOf(ref.treeUri)?.toString() ?: ref.treeUri,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Spacer(Modifier.height(Spacing.Large))

        if (stores.isEmpty()) {
            // Bounded height here — this column does not scroll — so the state can centre itself
            // in what is left of the window.
            EmptyState(
                icon = Icons.Filled.Password,
                title = tr("d_pass_empty_title"),
                message = tr("d_pass_empty_intro") + "\n\n" + tr("d_pass_empty_detail"),
                modifier = Modifier.fillMaxSize()
            ) {
                BrandButton(onClick = { showPicker = true }) { Text(tr("d_pass_add_store")) }
            }
            return@Column
        }

        walkError?.let {
            StatusStrip(it, error = true)
            Spacer(Modifier.height(Spacing.Medium))
        }

        Row(modifier = Modifier.fillMaxSize()) {
            // ── Browse pane ─────────────────────────────────────────────
            Column(modifier = Modifier.width(360.dp).fillMaxHeight()) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text(tr("d_pass_search_label")) },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    singleLine = true,
                    shape = RoundedCornerShape(Radius.Small),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(Spacing.Medium))

                val root = tree
                if (root == null) {
                    Text(
                        tr("d_pass_no_entries"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else if (query.isNotBlank()) {
                    val hits = remember(root, query) { DesktopPassStore.search(root, query) }
                    Text(
                        trQuantity("d_pass_match_count", hits.size),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(4.dp))
                    LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(hits, key = { it.id }) { entry ->
                            EntryRow(
                                label = entry.relativePath,
                                selected = selectedEntry?.id == entry.id,
                                onClick = { selectedEntry = entry }
                            )
                        }
                    }
                } else {
                    val folder = remember(root, folderPath) {
                        DesktopPassStore.folderAt(root, folderPath) ?: root
                    }
                    // Breadcrumb
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (folderPath.isNotEmpty()) {
                            IconButton(onClick = {
                                folderPath = folderPath.substringBeforeLast('/', "")
                            }) { Icon(Icons.Filled.ArrowBack, contentDescription = tr("d_pass_up")) }
                        }
                        Text(
                            if (folderPath.isEmpty()) root.folderName else folderPath,
                            style = MaterialTheme.typography.titleSmall
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                    LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(folder.children, key = { it.id }) { node ->
                            when (node) {
                                is PassNode.Folder -> FolderRow(node.folderName) { folderPath = node.path }
                                is PassNode.Entry -> EntryRow(
                                    label = node.entryName,
                                    selected = selectedEntry?.id == node.id,
                                    onClick = { selectedEntry = node }
                                )
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.width(Spacing.Section))

            // ── Entry pane ──────────────────────────────────────────────
            Box(modifier = Modifier.fillMaxSize()) {
                val entry = selectedEntry
                val ref = selectedStore
                if (entry == null || ref == null) {
                    EmptyState(
                        icon = Icons.Filled.Password,
                        title = tr("d_pass_select_entry_title"),
                        message = tr("d_pass_select_entry"),
                        modifier = Modifier.fillMaxSize()
                    )
                } else {
                    EntryPane(state, ref, entry, scope)
                }
            }
        }
    }

    if (showPicker) StoreFolderDialog { dir -> showPicker = false; dir?.let { addStore(it) } }
}

/**
 * A row in the browse pane.
 *
 * D12 — the two row kinds share one shape now. Selection used to be `secondaryContainer`, a
 * scheme colour neither the Android app nor anything else in this window uses, which read as a
 * different app's highlight; it is the brand wash instead, with the leading icon picking up the
 * accent so the selected row is legible at a glance in both schemes.
 */
@Composable
private fun PassRow(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    selected: Boolean,
    onClick: () -> Unit
) {
    val shape = RoundedCornerShape(Radius.Small)
    Box(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp)
            .clip(shape)
            .then(if (selected) Modifier.background(Brand.gradientWash(0.20f)) else Modifier)
            .clickable(onClick = onClick)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = Spacing.Small, vertical = Spacing.Small)
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = if (selected) Brand.Accent else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp)
            )
            Spacer(Modifier.width(Spacing.Small))
            Text(
                label,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}

@Composable
private fun FolderRow(name: String, onClick: () -> Unit) =
    PassRow(name, Icons.Filled.Folder, selected = false, onClick = onClick)

@Composable
private fun EntryRow(label: String, selected: Boolean, onClick: () -> Unit) =
    PassRow(label, Icons.Filled.Lock, selected = selected, onClick = onClick)

// ── The entry pane ─────────────────────────────────────────────────────

@Composable
private fun EntryPane(
    state: DesktopState,
    ref: PassStoreRef,
    entry: PassNode.Entry,
    scope: kotlinx.coroutines.CoroutineScope
) {
    val repo = state.repository
    var entryState by remember(entry.id) { mutableStateOf<EntryState>(EntryState.Locked) }
    var passphrase by remember(entry.id) { mutableStateOf("") }
    var reveal by remember(entry.id) { mutableStateOf(false) }
    var pendingCardOp by remember(entry.id) { mutableStateOf<CardOpRequest?>(null) }
    var clipboardCountdown by remember { mutableStateOf<Int?>(null) }

    val recipients = remember(ref.id, entry.id) {
        DesktopPassStore.recipientsForEntry(ref, entry.relativePath)
    }

    // Read the ciphertext once per selection; routing and retries reuse it.
    val bytes = remember(ref.id, entry.id) { DesktopPassStore.readEntryBytes(ref, entry.relativePath) }

    suspend fun attemptSoftware(rings: List<org.bouncycastle.openpgp.PGPSecretKeyRing>, pass: String?, retry: Boolean) {
        val data = bytes ?: run {
            entryState = EntryState.Failed(tr("d_pass_entry_missing"))
            return
        }
        entryState = EntryState.Working
        val result = withContext(Dispatchers.Default) {
            runCatching { PassDecryptCoordinator.decryptSoftware(data, rings, pass) }
        }
        entryState = result.fold(
            onSuccess = { EntryState.Shown(PassEntryParser.parse(it)) },
            onFailure = { EntryState.PassphraseNeeded(retry = retry) }
        )
    }

    fun unlock() {
        scope.launch {
            val data = bytes ?: run {
                entryState = EntryState.Failed(tr("d_pass_entry_missing"))
                return@launch
            }
            entryState = EntryState.Working
            when (val route = withContext(Dispatchers.Default) { PassDecryptCoordinator.route(repo, data) }) {
                is PassRoute.Software -> attemptSoftware(route.rings, null, retry = false)
                PassRoute.Card -> entryState = EntryState.CardNeeded
                PassRoute.NoMatch ->
                    entryState = EntryState.Failed(tr("d_pass_no_matching_key"))
            }
        }
    }

    // Auto-relock: decrypted content never sits on screen indefinitely (the desktop stand-in for
    // Android's biometric gate). Restarts whenever the shown content changes.
    LaunchedEffect(entryState) {
        if (entryState is EntryState.Shown) {
            delay(RELOCK_SECONDS * 1000L)
            entryState = EntryState.Locked
            passphrase = ""
            reveal = false
        }
    }

    // Clipboard countdown ticker (only while something is armed).
    LaunchedEffect(Unit) {
        while (true) {
            clipboardCountdown = DesktopClipboard.secondsRemaining
            delay(500)
        }
    }

    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Text(
            entry.entryName,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurface
        )
        Spacer(Modifier.height(Spacing.Tight))
        Text(
            entry.relativePath,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        if (recipients.isNotEmpty()) {
            Text(
                tr("d_pass_encrypted_to", recipients.joinToString(", ")),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(Modifier.height(Spacing.Medium))
        BrandRule()
        Spacer(Modifier.height(Spacing.Large))

        when (val s = entryState) {
            EntryState.Locked -> {
                BrandButton(onClick = { unlock() }, enabled = bytes != null) {
                    Text(tr("pass_entry_decrypt"))
                }
                if (bytes == null) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        tr("pass_entry_unreadable"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }

            EntryState.Working -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(modifier = Modifier.width(18.dp).height(18.dp))
                Spacer(Modifier.width(10.dp))
                Text(tr("d_pass_decrypting"), style = MaterialTheme.typography.bodyMedium)
            }

            is EntryState.PassphraseNeeded -> Column {
                Text(
                    if (s.retry) tr("pass_entry_passphrase_wrong")
                    else tr("pass_entry_passphrase_hint"),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (s.retry) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.onSurface
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(tr("pass_entry_passphrase_label")) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.width(320.dp)
                )
                Spacer(Modifier.height(8.dp))
                BrandButton(
                    enabled = passphrase.isNotEmpty(),
                    onClick = {
                        scope.launch {
                            val data = bytes ?: return@launch
                            val route = withContext(Dispatchers.Default) {
                                PassDecryptCoordinator.route(repo, data)
                            }
                            if (route is PassRoute.Software) {
                                attemptSoftware(route.rings, passphrase, retry = true)
                            }
                        }
                    }
                ) { Text(tr("pass_entry_unlock")) }
            }

            EntryState.CardNeeded -> Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.CreditCard, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        tr("d_pass_card_entry"),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                Spacer(Modifier.height(8.dp))
                BrandButton(onClick = {
                    scope.launch {
                        val data = bytes ?: return@launch
                        val match = DesktopCardOps.matchCardDecryptKey(data, repo)
                        if (match == null) {
                            entryState = EntryState.Failed(tr("d_pass_card_key_missing"))
                            return@launch
                        }
                        entryState = EntryState.CardWaiting
                        pendingCardOp = CardOpRequest(
                            tr(
                                "d_pass_card_decrypt_title",
                                entry.entryName,
                                match.entity.userID.ifBlank { tr("d_crypto_hardware_key") }
                            )
                        ) { session, pin ->
                            val r = com.pgpony.android.crypto.card.CardDecryptService.shared
                                .decryptBytes(session, match.ring, pin, data)
                            entryState = EntryState.Shown(
                                PassEntryParser.parse(r.data.toString(Charsets.UTF_8))
                            )
                        }
                    }
                }) { Text(tr("pass_entry_card_decrypt")) }
            }

            EntryState.CardWaiting -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(modifier = Modifier.width(18.dp).height(18.dp))
                Spacer(Modifier.width(10.dp))
                Text(tr("provider_cardop_waiting"), style = MaterialTheme.typography.bodyMedium)
            }

            is EntryState.Shown -> ShownContent(
                content = s.content,
                reveal = reveal,
                onToggleReveal = { reveal = !reveal },
                onRelock = {
                    entryState = EntryState.Locked; passphrase = ""; reveal = false
                },
                clipboardCountdown = clipboardCountdown,
                onStatus = { state.status = it }
            )

            is EntryState.Failed -> Column {
                Text(s.message, color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = { entryState = EntryState.Locked }) { Text(tr("common_button_back")) }
            }
        }
    }

    pendingCardOp?.let { request ->
        CardOpDialog(request) { ok, message ->
            pendingCardOp = null
            if (!ok) {
                entryState = if (message == null) EntryState.CardNeeded
                else EntryState.Failed(tr("d_pass_card_failed", message))
            }
        }
    }
}

@Composable
private fun ShownContent(
    content: PassEntryContent,
    reveal: Boolean,
    onToggleReveal: () -> Unit,
    onRelock: () -> Unit,
    clipboardCountdown: Int?,
    onStatus: (String) -> Unit
) {
    Column {
        SubHeading(tr("pass_entry_password_label"))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (content.password.isEmpty()) tr("pass_entry_empty_password")
                else if (reveal) content.password else "•".repeat(content.password.length.coerceAtMost(24)),
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Medium
            )
            Spacer(Modifier.width(8.dp))
            IconButton(onClick = onToggleReveal) {
                Icon(
                    if (reveal) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                    contentDescription = if (reveal) tr("d_common_hide") else tr("d_common_reveal")
                )
            }
            IconButton(
                enabled = content.password.isNotEmpty(),
                onClick = {
                    DesktopClipboard.copy(content.password)
                    onStatus(
                        if (DesktopClipboard.autoClear())
                            tr("d_pass_password_copied_clearing", DesktopClipboard.clearSeconds())
                        else tr("d_pass_password_copied")
                    )
                }
            ) { Icon(Icons.Filled.ContentCopy, contentDescription = tr("d_pass_copy_password")) }
        }

        clipboardCountdown?.let { left ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    tr("d_pass_clipboard_countdown", left),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = { DesktopClipboard.clearNow() }) { Text(tr("d_common_clear_now")) }
            }
        }

        if (content.fields.isNotEmpty()) {
            Spacer(Modifier.height(Spacing.Section))
            SubHeading(tr("d_pass_fields"))
            content.fields.forEach { field ->
                Card(
                    shape = RoundedCornerShape(Radius.Small),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    ),
                    modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(horizontal = Spacing.Medium, vertical = Spacing.Small)
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                field.key,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(field.value, style = MaterialTheme.typography.bodyMedium)
                        }
                        IconButton(onClick = {
                            DesktopClipboard.copy(field.value)
                            onStatus(tr("d_pass_field_copied", field.key))
                        }) {
                            Icon(
                                Icons.Filled.ContentCopy,
                                contentDescription = tr("d_pass_copy_field", field.key)
                            )
                        }
                    }
                }
            }
        }

        content.otpauth?.let { uri -> OtpSection(uri, onStatus) }

        if (content.extraLines.isNotEmpty()) {
            Spacer(Modifier.height(Spacing.Section))
            SubHeading(tr("pass_entry_notes_label"))
            Text(
                content.extraLines.joinToString("\n"),
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace
            )
        }

        Spacer(Modifier.height(Spacing.Section))
        WrapRow(horizontalSpacing = Spacing.Medium) {
            OutlinedButton(onClick = onRelock, shape = RoundedCornerShape(Radius.Small)) {
                Text(tr("d_pass_lock"))
            }
            Text(
                tr("d_pass_relock_note", RELOCK_SECONDS),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun OtpSection(uri: String, onStatus: (String) -> Unit) {
    val config = remember(uri) { PassTotp.parse(uri) }

    Spacer(Modifier.height(Spacing.Section))
    SubHeading(tr("pass_entry_otp_label"))

    if (config == null) {
        // Not a TOTP URI (hotp, a bad secret, an algorithm we don't do). Show it rather than
        // swallow it — the user's authenticator app may well understand it.
        Text(uri, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
        Text(
            tr("d_pass_otp_unparsable"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(4.dp))
        OutlinedButton(onClick = {
            DesktopClipboard.copy(uri)
            onStatus(tr("d_pass_otp_uri_copied"))
        }) { Text(tr("d_pass_copy_uri")) }
        return
    }

    // One tick a second. `now` is the whole clock source: the code is a pure function of it,
    // so there is no timer state to get out of sync with the display.
    var now by remember(uri) { mutableStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(uri) {
        while (true) {
            delay(1000)
            now = System.currentTimeMillis() / 1000
        }
    }
    val step = now / config.periodSeconds
    val code = remember(config, step) { PassTotp.code(config, now) }
    val remaining = PassTotp.secondsRemaining(config, now)
    var showUri by remember(uri) { mutableStateOf(false) }

    if (code == null) {
        Text(
            tr("d_pass_otp_no_provider", config.algorithm),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error
        )
        return
    }

    // WrapRow: "läuft in %d s ab" and 「%d 秒後に更新」 are both wider than the English, and this
    // row already carries a headline-sized monospace code that will not give width back.
    WrapRow(horizontalSpacing = Spacing.Small) {
        Text(
            PassTotp.grouped(code),
            style = MaterialTheme.typography.headlineSmall,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurface
        )
        IconButton(onClick = {
            DesktopClipboard.copy(code)
            onStatus(
                if (DesktopClipboard.autoClear())
                    tr("d_pass_code_copied_clearing", DesktopClipboard.clearSeconds())
                else tr("d_pass_code_copied")
            )
        }) { Icon(Icons.Filled.ContentCopy, contentDescription = tr("d_pass_copy_code")) }
        BrandBadge(
            tr("d_pass_otp_rolls_in", remaining),
            if (remaining <= 5) BadgeTone.Error else BadgeTone.Neutral
        )
    }
    Text(
        tr(
            "d_pass_otp_meta",
            config.label, config.algorithm, config.digits, config.periodSeconds
        ),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )

    Spacer(Modifier.height(4.dp))
    WrapRow(horizontalSpacing = Spacing.Tight) {
        // The URI embeds the TOTP secret, so it stays folded away by default — but it is the
        // only way to move this entry into another authenticator, so it stays reachable.
        TextButton(onClick = { showUri = !showUri }) {
            Text(if (showUri) tr("d_pass_hide_uri") else tr("d_pass_show_uri"))
        }
        TextButton(onClick = {
            DesktopClipboard.copy(uri)
            onStatus(tr("d_pass_otp_uri_copied"))
        }) { Text(tr("d_pass_copy_setup_uri")) }
    }
    if (showUri) {
        Text(uri, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
    }
}

// ── Folder picker ──────────────────────────────────────────────────────

/**
 * Pick a store folder. macOS gets the native FileDialog (with the Apple directory flag, the only
 * way AWT's dialog selects folders); Windows and Linux get Swing's JFileChooser in
 * DIRECTORIES_ONLY mode, since FileDialog there can only select files.
 */
@Composable
private fun StoreFolderDialog(onResult: (File?) -> Unit) {
    val mac = remember { System.getProperty("os.name").lowercase().contains("mac") }
    if (mac) {
        AwtWindow(
            create = {
                System.setProperty("apple.awt.fileDialogForDirectories", "true")
                object : FileDialog(null as Frame?, tr("d_pass_choose_folder"), LOAD) {
                    override fun setVisible(visible: Boolean) {
                        super.setVisible(visible)
                        if (visible) {
                            val picked = file?.let { File(directory, it) }
                            System.setProperty("apple.awt.fileDialogForDirectories", "false")
                            onResult(picked)
                        }
                    }
                }
            },
            dispose = FileDialog::dispose
        )
    } else {
        LaunchedEffect(Unit) {
            onResult(withContext(Dispatchers.IO) { chooseDirectorySwing() })
        }
    }
}

/** Swing's directory chooser, shown on the EDT and awaited. */
private fun chooseDirectorySwing(): File? {
    var chosen: File? = null
    val show = Runnable {
        val chooser = JFileChooser().apply {
            dialogTitle = tr("d_pass_choose_folder")
            fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            isMultiSelectionEnabled = false
            currentDirectory = DesktopPassStore.defaultStorePath().toFile()
                .takeIf { it.isDirectory } ?: File(System.getProperty("user.home") ?: ".")
        }
        if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
            chosen = chooser.selectedFile
        }
    }
    if (SwingUtilities.isEventDispatchThread()) show.run()
    else runCatching { SwingUtilities.invokeAndWait(show) }
    return chosen
}
