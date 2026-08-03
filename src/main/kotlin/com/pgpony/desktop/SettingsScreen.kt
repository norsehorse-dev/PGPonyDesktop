// SettingsScreen.kt
// PGPony Desktop — D1 settings: theme picker (System/Light/Dark, persisted) + app info.
// D4: the Network section — proxy modes (Off / Tor / Custom SOCKS, the Android ProxyPrefs
// model with "Orbot" as the local-Tor-daemon mode), the keys.pgpony.app onion mirror, the
// ordered keyserver directory (toggle lookup/publish, reorder, add, remove, reset), and the
// auto-refresh switch.
//
// D11 — this is the screen the localization work landed on first, and it is the pattern for the
// rest: every user-visible literal became a tr() call, sentences the Android app already says
// reuse ITS key (settings_title, settings_section_backup, keyservers_reset, the theme names…)
// and only genuinely desktop-specific wording got a new `d_`-prefixed key in i18n/. Appearance
// gained the language picker itself — a plain DropdownMenu, because this project uses no
// experimental Compose APIs and ExposedDropdownMenuBox is one.
//
// Then the outbound links: About grew the repo / issue tracker / website rows and a paste-ready
// runtime line, Storage grew "Open folder" and "Copy path" (a desktop user can act on a path; an
// Android user has no file manager to hand one to), and a new "More from NorseHorse" section lists
// the rest of the app family with their real App Store icons. The link plumbing — the browser
// handoff, the icon cache, the row composables — lives in AppLinks.kt.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.pass.PassStorePrefs
import com.pgpony.android.keyserver.KeyServer
import com.pgpony.android.keyserver.KeyServerDirectory
import com.pgpony.android.network.HttpClientFactory
import com.pgpony.android.network.ProxyPrefs
import kotlinx.coroutines.launch
import java.util.UUID

@Composable
fun SettingsScreen(state: DesktopState) {
    val current by ThemeState.current
    var showExportBackup by remember { mutableStateOf(false) }
    var showRestoreBackup by remember { mutableStateOf(false) }
    var restoreInitialFile by remember { mutableStateOf<java.io.File?>(null) }

    // D9 — restore opened from the menu bar (no file) or from opening a .pgpony file.
    LaunchedEffect(state.uiRequest) {
        if (state.uiRequest == UiRequest.RESTORE) {
            restoreInitialFile = null; showRestoreBackup = true; state.consumeUiRequest()
        }
    }
    LaunchedEffect(state.pendingOpen) {
        (state.pendingOpen as? OpenAction.RestoreBackup)?.let { a ->
            restoreInitialFile = a.path.toFile(); showRestoreBackup = true; state.consumePendingOpen()
        }
    }

    // D12 batch 2 — seven groups of unrelated controls used to be separated by nothing but a
    // 20dp Spacer, so where one section ended and the next began was a judgement call the reader
    // had to make from type size alone. Each is now a SectionCard: one radius, one inset, one
    // gradient-ticked heading, and a subtitle carrying the note that used to trail the controls.
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(Spacing.Section)
            .verticalScroll(rememberScrollState())
    ) {
        ScreenHeader(title = tr("settings_title"), subtitle = tr("d_settings_subtitle"))
        Spacer(Modifier.height(Spacing.Section))

        // ── Network (D4) ────────────────────────────────────────────────
        SectionCard(tr("d_settings_section_network"), tr("d_settings_network_note")) {
            NetworkSection(state)
        }
        Spacer(Modifier.height(Spacing.Large))

        // ── SSH agent (D15) ─────────────────────────────────────────────
        SectionCard(tr("d_settings_section_ssh_agent"), tr("d_settings_ssh_agent_note")) {
            SshAgentSection(state)
        }
        Spacer(Modifier.height(Spacing.Large))

        // ── Watch folders (D18) ─────────────────────────────────────────
        SectionCard(tr("d_settings_section_watch"), tr("d_settings_watch_note")) {
            WatchSection(state)
        }
        Spacer(Modifier.height(Spacing.Large))

        // ── Backup (D6) ─────────────────────────────────────────────────
        SectionCard(tr("settings_section_backup"), tr("d_settings_backup_note")) {
            WrapRow {
                OutlinedButton(onClick = { showExportBackup = true }) {
                    Text(tr("d_settings_backup_export"))
                }
                OutlinedButton(onClick = { showRestoreBackup = true }) {
                    Text(tr("d_settings_backup_restore"))
                }
            }
        }
        Spacer(Modifier.height(Spacing.Large))

        // ── Password store (D8) ─────────────────────────────────────────
        SectionCard(tr("settings_section_pass_store"), tr("d_settings_pass_note")) {
            PassStoreSection(state)
        }
        Spacer(Modifier.height(Spacing.Large))

        // ── Appearance + language (D11) ─────────────────────────────────
        SectionCard(tr("settings_section_appearance"), tr("d_settings_appearance_note")) {
            AppTheme.entries.forEach { theme ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = current == theme, onClick = { ThemeState.set(theme) })
                    Text(tr(theme.labelKey), style = MaterialTheme.typography.bodyLarge)
                }
            }
            Spacer(Modifier.height(Spacing.Medium))
            LanguagePicker()
        }
        Spacer(Modifier.height(Spacing.Large))

        // ── Storage ─────────────────────────────────────────────────────
        SectionCard(tr("d_settings_section_storage")) {
            LabeledValue(
                label = tr("d_settings_storage_data_folder"),
                value = Config.dataDir.toString(),
                monospace = true
            )
            Spacer(Modifier.height(Spacing.Medium))
            // The path above is monospace text, which on desktop is the one thing a user cannot do
            // anything with. These two buttons are the desktop-native affordances Android has no
            // equivalent for: there is no file manager to hand an app-private directory to.
            WrapRow {
                OutlinedButton(onClick = { openFolder(Config.dataDir.toFile(), state) }) {
                    Text(tr("d_settings_storage_open_folder"))
                }
                OutlinedButton(onClick = {
                    DesktopClipboard.copy(Config.dataDir.toString(), secret = false)
                    state.status = tr("d_status_copied")
                }) {
                    Text(tr("d_settings_storage_copy_path"))
                }
            }
            Spacer(Modifier.height(Spacing.Small))
            Text(
                tr("d_settings_storage_note"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(Modifier.height(Spacing.Large))

        // ── Updates (D13) ───────────────────────────────────────────────
        // Sits directly above About, because the version number there is the thing this section
        // is talking about. UpdateSection lives in UpdateCheck.kt beside the logic it drives.
        SectionCard(tr("d_settings_section_updates"), tr("d_settings_updates_note")) {
            UpdateSection(state)
        }
        Spacer(Modifier.height(Spacing.Large))

        SectionCard(tr("settings_section_about"), tr("d_settings_about_note")) {
            AboutSection(state)
        }
        Spacer(Modifier.height(Spacing.Large))

        SectionCard(tr("d_settings_section_apps"), tr("d_settings_apps_note")) {
            AppFamilySection(state)
        }
        Spacer(Modifier.height(Spacing.Medium))
    }

    if (showExportBackup) ExportBackupDialog(state) { showExportBackup = false }
    if (showRestoreBackup) RestoreBackupDialog(state, restoreInitialFile) { showRestoreBackup = false }
}

// ── About ──────────────────────────────────────────────────────────────
//
// Android's About screen is one line, because a phone user who wants the source taps through to a
// store listing. A desktop user has nowhere to tap: no store page, no update channel, no obvious
// place to file a bug. So this section carries the three links that make the app locatable — the
// repo, its issue tracker, the site — plus the runtime line, which is the first thing anyone will
// ask for in a bug report and the last thing a user can be expected to find on their own.

@Composable
private fun AboutSection(state: DesktopState) {
    // D12 — the mark, then the version beside it. "PGPony Desktop" is the product name and stays
    // a literal, the same call the window title and the tray tooltip make.
    Row(verticalAlignment = Alignment.CenterVertically) {
        BrandMark(size = 48.dp)
        Spacer(Modifier.width(Spacing.Medium))
        Column {
            Text(
                "PGPony Desktop",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                tr("d_settings_about_version", AppVersion.VERSION),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }

    Spacer(Modifier.height(Spacing.Large))
    LinkRow("d_settings_about_repo", Links.REPO, state)
    Text(
        tr("d_settings_about_repo_note"),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    LinkRow("d_settings_about_issues", Links.ISSUES, state)
    LinkRow("d_settings_about_website", Links.WEBSITE, state)

    // Java version, OS and architecture: all proper nouns and numbers, so the value needs no
    // translation and only its label is a resource key — same shape as "Data folder" above. The
    // WrapRow inside LabeledValue is what keeps the copy button on screen once the German label
    // and a long Linux runtime string are competing for the same line.
    Spacer(Modifier.height(Spacing.Medium))
    LabeledValue(
        label = tr("d_settings_about_runtime_label"),
        value = runtimeDescription(),
        monospace = true
    ) {
        TextButton(onClick = {
            DesktopClipboard.copy(
                "PGPony Desktop ${AppVersion.VERSION}\n${runtimeDescription()}",
                secret = false
            )
            state.status = tr("d_status_copied")
        }) { Text(tr("d_settings_about_copy_diagnostics")) }
    }
}

/**
 * One line, paste-ready for a bug report.
 *
 * `internal`, not file-private: D12 batch 3's About dialog shows the same line, and two copies of
 * this would drift the first time someone added the CPU count to one of them.
 */
internal fun runtimeDescription(): String {
    fun p(name: String) = System.getProperty(name).orEmpty()
    return "Java ${p("java.version")} · ${p("os.name")} ${p("os.version")} (${p("os.arch")})"
}

// ── More from NorseHorse ───────────────────────────────────────────────
//
// The rest of the family. Every row is a link to that app's own site rather than to a store
// listing: the store a given user wants depends on their phone, two of these ship on F-Droid as
// well, and one is not on any store yet — the site is the one address that is correct for all of
// them and stays correct when that changes.

@Composable
private fun AppFamilySection(state: DesktopState) {
    PonyApps.ALL.forEach { app -> AppLinkRow(app, state) }
}

// ── Language picker (D11) ──────────────────────────────────────────────
//
// A plain DropdownMenu anchored to an OutlinedButton, not ExposedDropdownMenuBox: that one is
// still @ExperimentalMaterial3Api, and this project carries no @OptIn anywhere.
//
// Switching is instant and needs no restart. `tr()` reads I18n.language, which is snapshot state,
// so every composable that drew a translated string is subscribed and the whole window — this
// screen, the nav rail, any open dialog — recomposes on the next frame.

@Composable
private fun LanguagePicker() {
    var expanded by remember { mutableStateOf(false) }
    // Read once per composition so the button label follows the selection.
    val selected = I18n.language
    val systemLabel = tr("d_settings_language_system", I18n.displayNameOf(I18n.systemMatch()))
    val buttonLabel =
        if (selected == I18n.SYSTEM) systemLabel else I18n.displayNameOf(selected)

    SubHeading(tr("settings_language_row_title"))
    Box {
        OutlinedButton(
            onClick = { expanded = true },
            shape = RoundedCornerShape(Radius.Small)
        ) {
            Text(buttonLabel)
            Spacer(Modifier.width(Spacing.Tight))
            Icon(Icons.Filled.ArrowDropDown, contentDescription = null)
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            DropdownMenuItem(
                text = { Text(systemLabel) },
                onClick = { I18n.selectLanguage(I18n.SYSTEM); expanded = false }
            )
            I18n.SUPPORTED.forEach { tag ->
                DropdownMenuItem(
                    text = { Text(I18n.displayNameOf(tag)) },
                    onClick = { I18n.selectLanguage(tag); expanded = false }
                )
            }
        }
    }
    Spacer(Modifier.height(Spacing.Small))
    Text(
        tr("d_settings_language_note"),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

// ── Network section (D4) ───────────────────────────────────────────────

private enum class ProxyChoice(val labelKey: String, val mode: String) {
    OFF("d_settings_proxy_off", ProxyPrefs.MODE_OFF),
    TOR("d_settings_proxy_tor", ProxyPrefs.MODE_ORBOT),
    CUSTOM("d_settings_proxy_custom", ProxyPrefs.MODE_CUSTOM);

    /** TOR names the local listener it expects, so its template takes the host and the port. */
    fun label(): String =
        if (this == TOR) tr(labelKey, ProxyPrefs.ORBOT_HOST, ProxyPrefs.ORBOT_PORT) else tr(labelKey)
}

@Composable
private fun NetworkSection(state: DesktopState) {
    val scope = rememberCoroutineScope()
    // Bump to re-read prefs/directory after every mutation.
    var version by remember { mutableStateOf(0) }
    val cfg = remember(version) { ProxyPrefs.config(PGPonyApp.instance) }
    val onionMirror = remember(version) { ProxyPrefs.onionMirror(PGPonyApp.instance) }
    val autoRefresh = remember(version) { DesktopNetworkPrefs.autoRefresh() }
    var customHost by remember { mutableStateOf("") }
    var customPort by remember { mutableStateOf("") }
    var servers by remember { mutableStateOf<List<KeyServer>>(emptyList()) }
    var showAddServer by remember { mutableStateOf(false) }
    val directory = remember { KeyServerDirectory.get(PGPonyApp.instance) }

    LaunchedEffect(version) {
        servers = runCatching { directory.readOnce() }.getOrDefault(KeyServerDirectory.DEFAULTS)
        if (cfg.mode == ProxyPrefs.MODE_CUSTOM) {
            if (customHost.isBlank()) customHost = cfg.host.orEmpty()
            if (customPort.isBlank()) customPort = cfg.port.takeIf { it > 0 }?.toString().orEmpty()
        }
    }

    fun proxyChanged() {
        HttpClientFactory.invalidate()
        version++
    }

    // The section's own heading and note are supplied by the enclosing SectionCard (D12); what
    // is left here are the two sub-groups, proxy and keyservers.
    SubHeading(tr("d_settings_proxy_title"))
    ProxyChoice.entries.forEach { choice ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(
                selected = cfg.mode == choice.mode,
                onClick = {
                    ProxyPrefs.setMode(PGPonyApp.instance, choice.mode)
                    proxyChanged()
                }
            )
            Text(choice.label(), style = MaterialTheme.typography.bodyMedium)
        }
    }
    if (cfg.mode == ProxyPrefs.MODE_ORBOT) {
        Text(
            tr("d_settings_proxy_tor_note", ProxyPrefs.ORBOT_HOST, ProxyPrefs.ORBOT_PORT),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
    if (cfg.mode == ProxyPrefs.MODE_CUSTOM) {
        // D12 — WrapRow, not Row: "Benutzerdefinierter SOCKS-Host" and "Port" are wider labels
        // than their English originals and the Apply button was the child getting squeezed.
        WrapRow(verticalSpacing = Spacing.Medium) {
            OutlinedTextField(
                value = customHost, onValueChange = { customHost = it },
                label = { Text(tr("settings_proxy_custom_host")) }, singleLine = true,
                shape = RoundedCornerShape(Radius.Small),
                modifier = Modifier.width(220.dp)
            )
            OutlinedTextField(
                value = customPort, onValueChange = { customPort = it },
                label = { Text(tr("settings_proxy_custom_port")) }, singleLine = true,
                isError = customPort.isNotBlank() && customPort.toIntOrNull() == null,
                shape = RoundedCornerShape(Radius.Small),
                modifier = Modifier.width(100.dp)
            )
            OutlinedButton(
                enabled = customHost.isNotBlank() && customPort.toIntOrNull() != null,
                shape = RoundedCornerShape(Radius.Small),
                onClick = {
                    ProxyPrefs.setCustom(PGPonyApp.instance, customHost.trim(), customPort.toInt())
                    proxyChanged()
                    state.status = tr("d_status_proxy_set", "${customHost.trim()}:$customPort")
                }
            ) { Text(tr("d_common_apply")) }
        }
    }
    if (cfg.enabled) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = onionMirror,
                onCheckedChange = {
                    ProxyPrefs.setOnionMirror(PGPonyApp.instance, it)
                    version++
                }
            )
            Text(
                tr("settings_proxy_onion_subtitle"),
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }

    Spacer(Modifier.height(Spacing.Large))
    SubHeading(tr("d_settings_keyservers_title"))
    servers.forEachIndexed { index, server ->
        Card(
            shape = RoundedCornerShape(Radius.Small),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(horizontal = Spacing.Medium, vertical = Spacing.Tight)
            ) {
                Column(Modifier.weight(1f)) {
                    Text(server.label, style = MaterialTheme.typography.bodyMedium)
                    Text(
                        server.baseUrl + if (server.isFirstParty) tr("d_keyservers_first_party") else "",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = server.lookupEnabled,
                        onCheckedChange = { enabled ->
                            scope.launch { directory.setLookupEnabled(server.id, enabled); version++ }
                        }
                    )
                    Text(tr("d_keyservers_lookup"), style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.width(Spacing.Small))
                    Checkbox(
                        checked = server.publishEnabled,
                        onCheckedChange = { enabled ->
                            scope.launch { directory.setPublishEnabled(server.id, enabled); version++ }
                        }
                    )
                    Text(tr("d_keyservers_publish"), style = MaterialTheme.typography.bodySmall)
                }
                IconButton(
                    enabled = index > 0,
                    onClick = { scope.launch { directory.move(server.id, up = true); version++ } }
                ) { Icon(Icons.Filled.ArrowUpward, contentDescription = tr("keyservers_move_up")) }
                IconButton(
                    enabled = index < servers.lastIndex,
                    onClick = { scope.launch { directory.move(server.id, up = false); version++ } }
                ) { Icon(Icons.Filled.ArrowDownward, contentDescription = tr("keyservers_move_down")) }
                if (server.id != KeyServerDirectory.ID_OPENPGP &&
                    server.id != KeyServerDirectory.ID_PGPONY
                ) {
                    IconButton(onClick = {
                        scope.launch { directory.save(servers.filter { it.id != server.id }); version++ }
                    }) { Icon(Icons.Filled.Delete, contentDescription = tr("d_keyservers_remove")) }
                }
            }
        }
    }
    Spacer(Modifier.height(Spacing.Small))
    WrapRow {
        OutlinedButton(onClick = { showAddServer = true }) { Text(tr("d_keyservers_add")) }
        OutlinedButton(onClick = {
            scope.launch { directory.resetToDefaults(); version++ }
        }) { Text(tr("keyservers_reset")) }
    }
    Spacer(Modifier.height(Spacing.Small))
    Text(
        tr("d_keyservers_note"),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )

    Spacer(Modifier.height(Spacing.Medium))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(
            checked = autoRefresh,
            onCheckedChange = {
                DesktopNetworkPrefs.setAutoRefresh(it)
                version++
            }
        )
        Text(
            tr("d_settings_autorefresh"),
            style = MaterialTheme.typography.bodyMedium
        )
    }

    if (showAddServer) {
        AddServerDialog(
            onDismiss = { showAddServer = false },
            onAdd = { label, baseUrl ->
                showAddServer = false
                scope.launch {
                    directory.save(
                        servers + KeyServer(
                            id = UUID.randomUUID().toString(),
                            label = label,
                            baseUrl = baseUrl.trimEnd('/'),
                            isFirstParty = false,
                            lookupEnabled = true,
                            publishEnabled = true,
                            // We don't presume to know a custom server's limits (R5 rule).
                            acceptsAllKeyTypes = true
                        )
                    )
                    version++
                    state.status = tr("d_status_keyserver_added", label)
                }
            }
        )
    }
}

// ── Password store section (D8) ────────────────────────────────────────
//
// Off by default, same as the Android app: a keyring app shouldn't grow a password-manager tab
// for the majority of users who have no `pass` store. The clipboard controls live here because
// D8 is the first surface that copies a secret — but they govern every secret copy in the app.

@Composable
private fun PassStoreSection(state: DesktopState) {
    // Same bump-to-re-read idiom as NetworkSection: these read java.util.prefs, not Compose state.
    var version by remember { mutableStateOf(0) }
    val autoClear = remember(version) { DesktopClipboard.autoClear() }
    val storeCount = remember(version, state.passEnabled) { PassStorePrefs.load().size }
    val defaultPath = remember { DesktopPassStore.defaultStorePath() }
    val defaultLooksReal = remember(version, state.passEnabled) {
        DesktopPassStore.looksLikeStore(defaultPath)
    }
    var secondsText by remember { mutableStateOf(DesktopClipboard.clearSeconds().toString()) }
    val secondsValue = secondsText.toIntOrNull()
    val secondsValid = secondsValue != null && secondsValue in 5..600

    // Heading and note come from the enclosing SectionCard (D12).
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(
            checked = state.passEnabled,
            onCheckedChange = { state.showPassStore(it) }
        )
        Text(
            tr("d_settings_pass_show_tab"),
            style = MaterialTheme.typography.bodyMedium
        )
    }

    if (state.passEnabled) {
        Spacer(Modifier.height(Spacing.Small))
        LabeledValue(
            label = tr("d_settings_pass_default_location"),
            value = defaultPath.toString(),
            monospace = true
        )
        Spacer(Modifier.height(Spacing.Tight))
        Text(
            when {
                // D11 — a real <plurals>, not "store(s)": German and Portuguese inflect the
                // noun and the pronoun after it, and Japanese has neither form.
                storeCount > 0 -> trQuantity("d_settings_pass_status_configured", storeCount)
                defaultLooksReal -> tr("d_settings_pass_status_exists")
                else -> tr("d_settings_pass_status_none")
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }

    Spacer(Modifier.height(Spacing.Large))
    SubHeading(tr("settings_section_clipboard"))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(
            checked = autoClear,
            onCheckedChange = { DesktopClipboard.setAutoClear(it); version++ }
        )
        Text(tr("d_settings_clipboard_autoclear"), style = MaterialTheme.typography.bodyMedium)
    }
    if (autoClear) {
        WrapRow(verticalSpacing = Spacing.Medium) {
            OutlinedTextField(
                value = secondsText,
                onValueChange = { secondsText = it.filter { c -> c.isDigit() }.take(3) },
                label = { Text(tr("d_settings_clipboard_seconds_label")) },
                singleLine = true,
                isError = secondsText.isNotBlank() && !secondsValid,
                shape = RoundedCornerShape(Radius.Small),
                modifier = Modifier.width(120.dp)
            )
            OutlinedButton(
                enabled = secondsValid && secondsValue != DesktopClipboard.clearSeconds(),
                shape = RoundedCornerShape(Radius.Small),
                onClick = {
                    DesktopClipboard.setClearSeconds(secondsValue!!)
                    version++
                    state.status = tr("d_status_clipboard_seconds", DesktopClipboard.clearSeconds())
                }
            ) { Text(tr("d_common_apply")) }
            OutlinedButton(
                onClick = { DesktopClipboard.clearNow() },
                shape = RoundedCornerShape(Radius.Small)
            ) {
                Text(tr("d_common_clear_now"))
            }
        }
        Spacer(Modifier.height(Spacing.Small))
        Text(
            tr("d_settings_clipboard_note"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun AddServerDialog(onDismiss: () -> Unit, onAdd: (label: String, baseUrl: String) -> Unit) {
    var label by remember { mutableStateOf("") }
    var baseUrl by remember { mutableStateOf("https://") }
    val urlOk = baseUrl.startsWith("https://") && baseUrl.length > 8 ||
        baseUrl.startsWith("http://") && baseUrl.length > 7

    BrandDialog(
        onDismissRequest = onDismiss,
        title = tr("d_keyservers_add_title"),
        content = {
            Column {
                OutlinedTextField(
                    value = label, onValueChange = { label = it },
                    label = { Text(tr("keyring_generate_name_label")) }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = baseUrl, onValueChange = { baseUrl = it },
                    label = { Text(tr("d_keyservers_add_url_label")) },
                    singleLine = true,
                    isError = baseUrl.isNotBlank() && !urlOk,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    tr("d_keyservers_add_note"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = label.isNotBlank() && urlOk,
                onClick = { onAdd(label.trim(), baseUrl.trim()) }
            ) { Text(tr("d_common_add")) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("common_button_cancel")) } }
    )
}
