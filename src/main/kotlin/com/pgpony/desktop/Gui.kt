// Gui.kt
// PGPony Desktop — window shell + navigation rail. D2a: state is backed by Room
// (DesktopKeyRepository) instead of the D1 JSON store; the legacy store migrates on first launch.
//
// D11b/D11c — localization. Everything a human reads here is a key: the status line, the tray
// menu, the expiration notifications, and the menu bar. Three things are deliberately NOT keys.
// "PGPony" (the tray tooltip and the window title) is the product name. KeyAlgorithm.displayName
// stays as it comes out of the vendored enum, because it is a spec name (Ed25519, RSA 4096) that
// should read the same in every language. TrustLevel.displayName and RevocationReason.displayName
// are BACKUP WIRE VALUES, so the status line routes them through trustName()/reasonName() in
// KeyDetailDialog.kt instead — those map the enum to a key at the UI boundary and leave the
// persisted value alone.
//
// Menu mnemonics are keys as well: 'F' for "File" does not appear in "Datei", so a hardcoded
// mnemonic silently stops matching its own menu the moment the app is translated.

package com.pgpony.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.MenuBar
import androidx.compose.ui.window.Notification
import androidx.compose.ui.window.Tray
import androidx.compose.ui.window.TrayState
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberTrayState
import androidx.compose.ui.window.rememberWindowState
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.awt.datatransfer.DataFlavor
import java.awt.dnd.DnDConstants
import java.awt.dnd.DropTarget
import java.awt.dnd.DropTargetAdapter
import java.awt.dnd.DropTargetDropEvent
import java.nio.file.Path

/** App-level state: Room-backed keyring (D2a) wrapped for Compose observation. */
class DesktopState(private val scope: CoroutineScope) {
    private val db = Db.open(Config.dbFile)
    val repository = DesktopKeyRepository(db, KeyMaterialStore(Config.keysDir))
    val keyRefresh = DesktopKeyRefresh(repository)

    var keys by mutableStateOf<List<PGPKeyEntity>>(emptyList())
        private set
    var status by mutableStateOf<String?>(null)
    var busy by mutableStateOf(false)
        private set

    /** D9 — the selected rail destination, hoisted so the menu bar, tray, and file-open
     *  routing can navigate. */
    var destination by mutableStateOf(Destination.Keyring)

    /** D9 — a menu-bar action a screen should act on (open a dialog). */
    var uiRequest by mutableStateOf<UiRequest?>(null)
    fun consumeUiRequest() { uiRequest = null }

    /**
     * D8 — whether the Password Store surface is shown. Off by default, matching the Android
     * app: a keyring app shouldn't grow a password-manager tab unless the user has a pass store.
     * Mirrored into Compose state (rather than read from Preferences at each composition) so the
     * Settings toggle moves the rail on the same frame.
     */
    var passEnabled by mutableStateOf(DesktopPassSettings.enabled())
        private set

    // Not named setPassEnabled: a `private set` on the property above still emits a JVM
    // setPassEnabled(Z)V, so that name is already taken and the declarations clash.
    fun showPassStore(value: Boolean) {
        DesktopPassSettings.setEnabled(value)
        passEnabled = value
        // Don't strand the user on a screen that just left the rail.
        if (!value && destination == Destination.Pass) destination = Destination.Keyring
    }

    /**
     * D15 — the ssh-agent toggle. Mirrored into Compose state so the Settings section shows
     * the socket line the same frame it starts. The listener's lifecycle rides this: on means
     * a bound socket, off means the socket is gone. Persisted-on keys restart the agent at
     * launch (init below).
     */
    var sshAgentEnabled by mutableStateOf(SshAgentPrefs.enabled())
        private set

    fun enableSshAgent(value: Boolean) {
        SshAgentPrefs.setEnabled(value)
        sshAgentEnabled = value
        if (value) SshAgentService.start(repository) else SshAgentService.stop()
    }

    /** D3b — files dropped on the window; consumed by the Files surface. D16: folders too, so a
     *  dropped directory can be tar-encrypted (§3a); the Files surface routes each by kind. */
    var droppedFiles by mutableStateOf<List<Path>>(emptyList())
        private set

    fun onFilesDropped(files: List<java.io.File>) {
        droppedFiles = files.filter { it.isFile || it.isDirectory }.map { it.toPath() }
        if (droppedFiles.isNotEmpty()) status = trQuantity("d_status_files_dropped", droppedFiles.size)
    }

    fun consumeDroppedFiles() {
        droppedFiles = emptyList()
    }

    /** D9 — a file opened via association / CLI arg / forwarded second launch, classified into
     *  an action for the screens to pick up (import, decrypt, encrypt, verify, restore). */
    var pendingOpen by mutableStateOf<OpenAction?>(null)
        private set

    fun consumePendingOpen() { pendingOpen = null }

    /** Route incoming file opens: a single file classifies to a typed action — honoring a
     *  forced op from `open --op` / a context-menu verb (D14) — and several files go to the
     *  Files surface as a batch (the drag-drop path), where the user picks the bulk operation
     *  themselves. A forced op on a batch is deliberately not pre-applied yet: the Files tab
     *  is the existing chooser, and pre-selecting its operation is 2a's installer-facing UI
     *  work, not routing. */
    private fun onOpenFiles(request: OpenRequest) {
        val paths = request.paths
        when {
            paths.size == 1 -> pendingOpen = DesktopFileRouter.classify(paths.first(), request.op)
            paths.size > 1 -> onFilesDropped(paths.map { it.toFile() })
        }
    }

    /** Re-query the keyring (e.g. after a backup restore). */
    fun reload() = scope.launch { refresh() }

    init {
        // D15 — an agent left enabled comes back up with the app (isSupported() gates Windows).
        if (sshAgentEnabled) SshAgentService.start(repository)

        // D9 — register with the open-file bus; drains any request passed on first launch.
        AppOpen.setHandler { request -> onOpenFiles(request) }
        scope.launch {
            repository.migrateLegacyJson(Config.legacyKeyringFile)?.let {
                status = tr("d_status_migrated_legacy", it.summary())
            }
            refresh()
        }
        // D4 — background refresh ticker (the Android Phase 7 worker's session-scoped analog):
        // keys not checked in 24h are refreshed against the directory every 12h while the app
        // runs. Quiet unless something actually changed; per-key failures stamp lastCheckedAt
        // and stay silent (offline sessions don't spam). Off switch in Settings → Network.
        scope.launch {
            kotlinx.coroutines.delay(INITIAL_REFRESH_DELAY_MS) // don't compete with startup
            while (true) {
                if (DesktopNetworkPrefs.autoRefresh()) autoRefreshPass()
                kotlinx.coroutines.delay(REFRESH_TICK_MS)
            }
        }
    }

    private suspend fun autoRefreshPass() {
        val cutoff = System.currentTimeMillis() - STALE_AFTER_MS
        val stale = repository.allKeys().filter { k ->
            !k.isRevoked && (k.lastCheckedAt ?: 0L) < cutoff
        }
        if (stale.isEmpty()) return
        var merged = 0
        var revoked = 0
        for (k in stale) {
            when (keyRefresh.refreshAcrossDirectory(k.fingerprint)) {
                is KeyRefreshResult.Merged -> merged++
                is KeyRefreshResult.RevokedUpstream -> revoked++
                else -> Unit
            }
        }
        if (merged > 0 || revoked > 0) {
            // Joined with d_list_separator rather than following the import summary's
            // convention (where every clause after the first carries its own leading separator),
            // because here either clause can be the one that comes first.
            val clauses = buildList {
                if (revoked > 0) add(trQuantity("d_status_autorefresh_revoked", revoked))
                if (merged > 0) add(trQuantity("d_status_autorefresh_updated", merged))
            }
            status = tr("d_status_autorefresh", clauses.joinToString(tr("d_list_separator")))
            refresh()
        }
    }

    private suspend fun refresh() {
        keys = repository.allKeys()
    }

    fun importArmoredText(text: String) = scope.launch {
        status = tr("d_status_import", repository.importArmoredText(text).summary())
        refresh()
    }

    fun importBytes(data: ByteArray) = scope.launch {
        status = tr("d_status_import", repository.importBytes(data).summary())
        refresh()
    }

    /** D2b — full Android generateKey port (incl. pre-cached revocation certificate).
     *  Returns immediately; completion lands in [status]. RSA-4096 can take a while. */
    fun generate(
        name: String,
        email: String,
        algorithm: com.pgpony.android.crypto.KeyAlgorithm,
        passphrase: String?,
        onDone: () -> Unit
    ) = scope.launch {
        busy = true
        // displayName is a spec name (Ed25519, RSA 4096) — an argument, not a key.
        status = tr("d_status_generating", algorithm.displayName)
        try {
            val entity = repository.generateKey(name, email, algorithm, passphrase)
            status = tr("d_status_generated", entity.userID, entity.shortFingerprint)
            refresh()
            onDone()
        } catch (t: Throwable) {
            status = tr("d_status_generate_failed", t.message ?: t::class.simpleName.orEmpty())
        } finally {
            busy = false
        }
    }

    fun delete(entity: PGPKeyEntity) = scope.launch {
        repository.deleteByFingerprint(entity.fingerprint)
        status = tr("d_status_deleted", entity.userID.ifBlank { entity.shortFingerprint })
        refresh()
    }

    // ── D2c mutations ───────────────────────────────────────────────────

    fun setTrust(entity: PGPKeyEntity, trust: com.pgpony.android.data.TrustLevel) = scope.launch {
        repository.updateTrustLevel(entity.fingerprint, trust)
        // trustName(), not trust.displayName: the latter is the backup wire value.
        status = tr("d_status_trust_set", trustName(trust), entity.shortFingerprint)
        refresh()
    }

    fun setNotes(entity: PGPKeyEntity, notes: String?) = scope.launch {
        repository.updateNotes(entity.fingerprint, notes)
        status = if (notes == null) tr("kd_vm_status_notes_cleared") else tr("kd_vm_status_notes_saved")
        refresh()
    }

    fun makeDefault(entity: PGPKeyEntity) = scope.launch {
        repository.setDefaultKey(entity.fingerprint)
        status = tr("kd_vm_status_set_as_default_format", entity.userID.ifBlank { entity.shortFingerprint })
        refresh()
    }

    fun setExpiration(entity: PGPKeyEntity, epochSeconds: Long?, passphrase: String?) = scope.launch {
        try {
            repository.setKeyExpirationSoftware(entity.fingerprint, epochSeconds, passphrase)
            status = if (epochSeconds == null) tr("d_status_expiration_removed")
            else tr("d_status_expiration_updated")
            refresh()
        } catch (t: Throwable) {
            status = tr("d_status_expiration_failed", t.message ?: t::class.simpleName.orEmpty())
        }
    }

    fun revoke(
        entity: PGPKeyEntity,
        reason: com.pgpony.android.data.RevocationReason,
        comment: String?,
        passphrase: String?,
        onDone: () -> Unit
    ) = scope.launch {
        busy = true
        try {
            repository.applyRevocation(entity.fingerprint, reason, comment, passphrase)
            // reasonName(), not reason.displayName: the latter is vendored enum text.
            status = tr("d_status_revoked", entity.userID.ifBlank { entity.shortFingerprint }, reasonName(reason))
            refresh()
            onDone()
        } catch (t: Throwable) {
            status = tr("kd_vm_error_revocation_failed_format", t.message ?: t::class.simpleName.orEmpty())
        } finally {
            busy = false
        }
    }

    /** Public armor for the clipboard; status feedback either way. */
    suspend fun publicArmorFor(entity: PGPKeyEntity): String? =
        repository.exportArmoredPublicKey(entity.fingerprint)

    // ── D4 — keyservers ─────────────────────────────────────────────────

    /** Detail-screen refresh: fetch from every lookup-enabled server, merge, report. */
    fun refreshKeyFromServers(entity: PGPKeyEntity) = scope.launch {
        busy = true
        status = tr("d_status_checking_servers", entity.shortFingerprint)
        try {
            // Five of the seven branches reuse the phone's keyserver wording verbatim. The
            // other three are desktop-owned: the phone has no "not published anywhere" outcome,
            // no keyring-row-vanished outcome, and no merged-as-well suffix (whose leading space
            // survives because the XML reader does not trim, and which ja renders with a
            // full-width parenthesis instead).
            status = when (val r = keyRefresh.refreshAcrossDirectory(entity.fingerprint)) {
                is KeyRefreshResult.UpToDate -> tr("kd_vm_refresh_up_to_date")
                is KeyRefreshResult.Merged -> tr("kd_vm_refresh_merged")
                is KeyRefreshResult.RevokedUpstream ->
                    tr("kd_vm_refresh_revoked") +
                        if (r.alsoMerged) tr("d_status_refresh_also_merged") else ""
                is KeyRefreshResult.NotFound -> tr("d_status_refresh_not_published")
                is KeyRefreshResult.FingerprintMismatch -> tr("kd_vm_refresh_mismatch")
                is KeyRefreshResult.Failed -> tr("kd_vm_refresh_failed_format", r.detail)
                KeyRefreshResult.KeyMissing -> tr("d_status_refresh_key_missing")
            }
            refresh()
        } finally {
            busy = false
        }
    }

    /**
     * Publish [entity]'s public key to [servers] (the dialog's checked set). Returns the
     * per-server outcomes for display; stamps lastUploadedAt when at least one accepted.
     */
    suspend fun publishTo(
        entity: PGPKeyEntity,
        servers: List<com.pgpony.android.keyserver.KeyServer>
    ): List<Pair<com.pgpony.android.keyserver.KeyServer, com.pgpony.android.keyserver.PublishOutcome>> {
        val armor = repository.exportArmoredPublicKey(entity.fingerprint) ?: return emptyList()
        val outcomes = servers.map { server ->
            server to com.pgpony.android.keyserver.MultiKeyServerService.shared.publish(server, armor)
        }
        if (outcomes.any { it.second is com.pgpony.android.keyserver.PublishOutcome.Ok }) {
            repository.markKeyServerUploaded(entity.fingerprint)
            refresh()
        }
        return outcomes
    }
}

// D4 ticker cadence: first pass 15s after launch, then every 12h; a key is stale after 24h.
private const val INITIAL_REFRESH_DELAY_MS = 15_000L
private const val REFRESH_TICK_MS = 12 * 60 * 60 * 1000L
private const val STALE_AFTER_MS = 24 * 60 * 60 * 1000L

// D9 — expiration reminder scan cadence: on launch, then daily while running.
private const val EXPIRY_SCAN_TICK_MS = 24 * 60 * 60 * 1000L

/** D9 — menu-bar requests a screen fulfills by opening a dialog. */
enum class UiRequest { NEW_KEY, RESTORE }

// Public (not private): DesktopState.destination and TrayNav.request reference it across the
// public surface, so a private enum would trip "exposes private type".
// D11 — `labelKey`, not `label`: an enum entry is a compile-time constant, so it cannot hold a
// translated string that has to change when the picker moves. It holds the resource key and the
// rail calls tr() at draw time. Three of the five keys are Android's (the rail and the phone's
// bottom bar name the same places); Crypto and Cards are desktop-owned because this window shows
// encrypt and decrypt on one surface and supports several card form factors over PC/SC.
enum class Destination(val labelKey: String, val icon: ImageVector, val enabled: Boolean, val note: String? = null) {
    Keyring("main_tab_keyring", Icons.Filled.VpnKey, true),
    Crypto("d_nav_crypto", Icons.Filled.Lock, true),
    Cards("d_nav_cards", Icons.Filled.CreditCard, true),            // D7 — PC/SC over USB
    Pass("d_pass_store_title", Icons.Filled.Password, true),          // D8 — hidden unless enabled
    Settings("main_tab_settings", Icons.Filled.Settings, true)
}

// D11 — the stored language is loaded before `application {}` starts composing, so the window
// never renders one English frame and then swaps. Split in two only to keep the body's
// indentation (and therefore its diff) untouched.
fun cmdGui() {
    I18n.init()
    guiApplication()
}

private fun guiApplication() = application {
    val windowState = rememberWindowState(width = 1150.dp, height = 780.dp)
    val trayState = rememberTrayState()

    // D11 — the tray menu lambda builds an AWT popup outside composition, so a tr() call in
    // there would never be re-read when the language changes. Resolving the labels out here, in
    // the composition, subscribes this scope to I18n.language and rebuilds the menu instead.
    val trayOpen = tr("d_tray_open")
    val trayEncrypt = tr("main_tab_encrypt")
    val trayKeyring = tr("main_tab_keyring")
    val trayQuit = tr("d_tray_quit")

    // D12 — the real app mark on every OS surface that shows one. Both files come out of
    // tools/make-icons.py; appIcon() decodes each once for the process. The stock padlock stays
    // as the fallback: a missing resource must degrade to a generic icon, never to no window.
    // rememberVectorPainter is called unconditionally (not inside the elvis) because a composable
    // that runs only on some frames changes the composition's group structure.
    val stockIcon = androidx.compose.ui.graphics.vector.rememberVectorPainter(Icons.Filled.Lock)
    val trayIcon = appIcon("pgpony_tray") ?: stockIcon
    val windowIcon = appIcon("pgpony_512") ?: stockIcon

    // D9 — system tray with quick actions + the channel key-expiration reminders post to.
    Tray(
        state = trayState,
        icon = trayIcon,
        tooltip = "PGPony",
        menu = {
            Item(trayOpen) { AppOpen.focusWindow?.invoke() }
            Item(trayEncrypt) { AppOpen.focusWindow?.invoke(); TrayNav.request = Destination.Crypto }
            Item(trayKeyring) { AppOpen.focusWindow?.invoke(); TrayNav.request = Destination.Keyring }
            Separator()
            Item(trayQuit) { exitApplication() }
        }
    )

    Window(
        onCloseRequest = ::exitApplication,
        state = windowState,
        title = "PGPony",
        icon = windowIcon
    ) {
        val scope = rememberCoroutineScope()
        val state = remember { DesktopState(scope) }

        // D9 — macOS "Open With" / Finder double-click delivers files to the RUNNING app via
        // this AWT handler (fires when the packaged app carries CFBundleDocumentTypes; harmless
        // no-op elsewhere). The CLI-arg + single-instance path covers Windows/Linux.
        LaunchedEffect(Unit) {
            runCatching {
                val desktop = java.awt.Desktop.getDesktop()
                if (desktop.isSupported(java.awt.Desktop.Action.APP_OPEN_FILE)) {
                    desktop.setOpenFileHandler { e ->
                        AppOpen.focusWindow?.invoke()
                        AppOpen.deliver(e.files.map { it.toPath() })
                    }
                }
            }
        }

        // D9 — window focus hook (a forwarded second launch / tray action raises the window).
        LaunchedEffect(Unit) {
            AppOpen.focusWindow = {
                window.isVisible = true
                if ((window.extendedState and java.awt.Frame.ICONIFIED) != 0) {
                    window.extendedState = window.extendedState and java.awt.Frame.ICONIFIED.inv()
                }
                window.toFront()
                window.requestFocus()
            }
        }

        // D9 — tray-menu navigation requests (set from outside composition).
        LaunchedEffect(Unit) {
            while (true) {
                TrayNav.request?.let { state.destination = it; TrayNav.request = null }
                kotlinx.coroutines.delay(150)
            }
        }

        // D15 — the ssh-agent's passphrase prompt, raised from the agent thread via the same
        // poll-a-volatile bridge as TrayNav. Rendered as a dialog; the agent thread is blocked
        // on the request's latch until the dialog completes it (or its 60s timeout fires).
        val agentUnlock = remember { mutableStateOf<AgentUnlockRequest?>(null) }
        LaunchedEffect(Unit) {
            while (true) {
                if (agentUnlock.value == null) agentUnlock.value = AgentPrompt.request
                kotlinx.coroutines.delay(150)
            }
        }
        agentUnlock.value?.let { req ->
            AgentUnlockDialog(req) { agentUnlock.value = null }
        }

        // D9 — key-expiration reminders. Re-scans whenever the keyring changes (it loads async
        // just after launch) and once a day thereafter; each (key, window) fires once per
        // session via the dedupe set.
        val seenExpiry = remember { mutableSetOf<String>() }
        LaunchedEffect(state.keys) {
            while (true) {
                ExpirationNotifier.due(state.keys, System.currentTimeMillis()).forEach { r ->
                    if (seenExpiry.add(r.dedupeKey)) {
                        trayState.sendNotification(
                            Notification(
                                title = if (r.urgent) tr("d_notif_key_expiring") else tr("d_notif_key_expiration"),
                                message = r.headline,
                                type = if (r.urgent) Notification.Type.Warning else Notification.Type.Info
                            )
                        )
                    }
                }
                kotlinx.coroutines.delay(EXPIRY_SCAN_TICK_MS)
            }
        }

        // D13 — the update check. OPT-IN: checkIfDue() returns immediately unless the user has
        // turned it on in Settings, which is off out of the box, so a default install makes no
        // request from here at all. Once enabled it still needs a day to have passed since the
        // last attempt, and that timestamp is persisted, so relaunching the app repeatedly cannot
        // turn this into a heartbeat. It never blocks the UI:
        // a failure leaves the Settings section reading "could not reach pgpony.app" and nothing
        // else in the app notices. See UpdateCheck.kt for what does and does not go over the wire.
        LaunchedEffect(Unit) {
            UpdateCheck.checkIfDue()
        }

        // D3b — window-level drag-drop via AWT DropTarget (no experimental Compose APIs).
        // Compose snapshot state accepts writes from the AWT EDT.
        LaunchedEffect(Unit) {
            window.dropTarget = DropTarget(window, object : DropTargetAdapter() {
                override fun drop(event: DropTargetDropEvent) {
                    try {
                        event.acceptDrop(DnDConstants.ACTION_COPY)
                        val dropped = (event.transferable
                            .getTransferData(DataFlavor.javaFileListFlavor) as? List<*>)
                            ?.filterIsInstance<java.io.File>()
                            .orEmpty()
                        if (dropped.isNotEmpty()) state.onFilesDropped(dropped)
                        event.dropComplete(true)
                    } catch (_: Throwable) {
                        event.dropComplete(false)
                    }
                }
            })
        }

        // D12 batch 3 — the About modal's open/closed flag. It lives HERE, in the window scope,
        // rather than inside App(): the menu bar and the theme block are siblings under
        // `Window { }`, and the item that opens the dialog is in the former while the dialog
        // itself has to compose inside the latter to inherit the color scheme.
        var showAbout by remember { mutableStateOf(false) }

        // D9 — native menu bar (the macOS app menu on macOS; a window menu elsewhere) with the
        // standard shortcuts. Navigation targets the hoisted state.destination.
        // The mnemonics are read from the locale (see the header note) and fall back to the
        // English letter if a translation ever ships an empty one. The shortcuts are NOT
        // localized: Cmd/Ctrl+1 is muscle memory and stays put in every language.
        MenuBar {
            Menu(tr("d_menu_file"), mnemonic = tr("d_menu_file_mnemonic").firstOrNull() ?: 'F') {
                Item(tr("d_menu_goto_keyring"), shortcut = shortcut(Key.I)) { state.destination = Destination.Keyring }
                Item(tr("d_menu_restore_backup")) { state.destination = Destination.Settings; state.uiRequest = UiRequest.RESTORE }
                Separator()
                Item(tr("d_menu_quit"), shortcut = shortcut(Key.Q)) { exitApplication() }
            }
            Menu(tr("d_menu_keys"), mnemonic = tr("d_menu_keys_mnemonic").firstOrNull() ?: 'K') {
                Item(tr("main_tab_keyring"), shortcut = shortcut(Key.One)) { state.destination = Destination.Keyring }
                Item(tr("d_menu_new_key"), shortcut = shortcut(Key.N)) { state.destination = Destination.Keyring; state.uiRequest = UiRequest.NEW_KEY }
                Item(tr("d_menu_hardware_keys"), shortcut = shortcut(Key.Three)) { state.destination = Destination.Cards }
                Item(
                    tr("d_pass_store_title"),
                    shortcut = shortcut(Key.Four),
                    enabled = state.passEnabled
                ) { state.destination = Destination.Pass }
            }
            Menu(tr("d_menu_message"), mnemonic = tr("d_menu_message_mnemonic").firstOrNull() ?: 'M') {
                Item(tr("d_menu_encrypt_decrypt"), shortcut = shortcut(Key.Two)) { state.destination = Destination.Crypto }
            }
            // D12 batch 3 — Help. Compose Desktop cannot add to macOS's application menu, where
            // an About item conventionally lives, so this is the one place that behaves the same
            // on macOS, Linux and Windows. No shortcut: About has no muscle memory to honour.
            Menu(tr("d_menu_help"), mnemonic = tr("d_menu_help_mnemonic").firstOrNull() ?: 'H') {
                Item(tr("d_menu_about")) { showAbout = true }
            }
        }

        PGPonyTheme {
            App(state)
            if (showAbout) AboutDialog(state) { showAbout = false }
        }
    }
}

@Composable
private fun App(state: DesktopState) {
    // Dropped files route to the Files surface.
    LaunchedEffect(state.droppedFiles) {
        if (state.droppedFiles.isNotEmpty()) state.destination = Destination.Crypto
    }

    // D9 — a classified file open switches to the owning screen; the screen consumes the
    // payload (import is handled here since it has no screen to preload).
    LaunchedEffect(state.pendingOpen) {
        when (val a = state.pendingOpen) {
            is OpenAction.ImportKey -> { state.importArmoredText(a.armored); state.destination = Destination.Keyring; state.consumePendingOpen() }
            is OpenAction.RestoreBackup -> state.destination = Destination.Settings
            is OpenAction.DecryptText, is OpenAction.EncryptText,
            is OpenAction.DecryptFile, is OpenAction.EncryptFile,
            is OpenAction.VerifyDetachedSignature -> state.destination = Destination.Crypto
            OpenAction.None, null -> Unit
        }
    }

    Surface(modifier = Modifier.fillMaxSize()) {
        Row(modifier = Modifier.fillMaxSize()) {
            // D12 — the rail carries the brand. The gradient goes on a Box behind it and the
            // rail itself is transparent, because NavigationRail's containerColor takes a Color
            // and a Brush is the only way to draw a gradient. The wash is kept faint on purpose:
            // the selected item's indicator and every label still have to clear contrast against
            // it in both the light and the dark scheme.
            //
            // D12 Fix2 — the rail's width is PINNED. `RailBrandHeader` fills its width (so the
            // mark, the wordmark and the rule centre themselves), and `NavigationRail` sizes
            // itself to its widest child. A Row measures its non-weighted children first with
            // the whole available width, so those two facts together made the rail as wide as
            // the window and left the destination Column measuring to zero — the whole app
            // rendered as a giant centred menu with no content pane. Pinning the container is
            // the fix; the header then fills 96dp instead of 1600.
            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .width(RAIL_WIDTH)
                    .background(Brand.gradientWash(0.10f))
            ) {
                NavigationRail(
                    modifier = Modifier.fillMaxHeight(),
                    containerColor = Color.Transparent,
                    header = { RailBrandHeader() }
                ) {
                    // D8 — the Password Store item is present only when enabled in Settings.
                    Destination.entries.filter { it != Destination.Pass || state.passEnabled }.forEach { dest ->
                        // D12 Fix3 — the item is pinned to the rail width and the label is
                        // centre-aligned. NavigationRailItem otherwise measures to its label's
                        // natural width, so a two-word label overflowed the pinned container and
                        // spilled its second line into the content pane, left-aligned. Pinning
                        // makes the label wrap INSIDE the rail; TextAlign.Center is what makes
                        // the wrapped second line sit under the first instead of beside it.
                        NavigationRailItem(
                            modifier = Modifier.width(RAIL_WIDTH),
                            selected = state.destination == dest,
                            onClick = { if (dest.enabled) state.destination = dest },
                            enabled = dest.enabled,
                            icon = { Icon(dest.icon, contentDescription = tr(dest.labelKey)) },
                            label = {
                                Text(
                                    tr(dest.labelKey),
                                    textAlign = TextAlign.Center,
                                    modifier = Modifier.fillMaxWidth()
                                )
                            }
                        )
                    }
                }
            }
            // weight(1f), not fillMaxSize: "take everything the rail did not" said explicitly,
            // rather than relying on the Row having any width left over to fill.
            Column(modifier = Modifier.weight(1f).fillMaxHeight()) {
                when (state.destination) {
                    Destination.Keyring -> KeyringScreen(state)
                    Destination.Crypto -> CryptoScreen(state)
                    Destination.Cards -> CardsScreen(state)
                    Destination.Pass -> PassScreen(state)
                    Destination.Settings -> SettingsScreen(state)
                }
            }
        }
    }
}

/**
 * The navigation rail's width.
 *
 * Material3's own default is 80dp, sized for an icon and a one-word label. This is wider because
 * the rail carries a 44dp app mark above the items, and because German compounds run long even
 * after D12 Fix3 shortened the destination labels to one word each — "Verschlüsseln" and
 * "Hardware-Schlüssel" are the two that set the floor.
 *
 * It is a hard width rather than a minimum on purpose: see the comment at the call site for what
 * happens when the rail is allowed to size itself to its content.
 */
private val RAIL_WIDTH = 112.dp

/**
 * D12 — the rail's masthead: the app mark, the wordmark, and a gradient rule closing the band off
 * from the destination list.
 *
 * "PGPony" is the product name, so it is a literal here and not a key — the same call the window
 * title and the tray tooltip make (see the file header).
 *
 * The `fillMaxWidth` below is only safe because the rail's container is pinned to [RAIL_WIDTH].
 */
@Composable
private fun RailBrandHeader() {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.fillMaxWidth().padding(top = Spacing.Large, bottom = Spacing.Small)
    ) {
        BrandMark(size = 44.dp)
        Spacer(Modifier.height(Spacing.Small))
        Text(
            "PGPony",
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface
        )
        Spacer(Modifier.height(Spacing.Medium))
        BrandRule(Modifier.padding(horizontal = Spacing.Large))
    }
}

/** D9 — tray-menu → window navigation bridge. The tray menu lives in the application scope
 *  (outside the Window content), so it can't touch DesktopState directly; the window polls
 *  this. */
object TrayNav {
    @Volatile var request: Destination? = null
}

/** Cross-platform accelerator: ⌘ on macOS, Ctrl elsewhere. */
private fun shortcut(key: Key): androidx.compose.ui.input.key.KeyShortcut {
    val mac = System.getProperty("os.name").lowercase().contains("mac")
    return androidx.compose.ui.input.key.KeyShortcut(key, meta = mac, ctrl = !mac)
}
