// AppLockScreen.kt
// PGPony Desktop 3.1.0 (plan section 2): the lock screen and the Settings section for the
// PGPony PIN, the duress PIN and the wrong-PIN wipe. The wording is PGPony Android's
// (applock_* strings, vendored), with desktop strings only where the phone's text talks about a
// phone or a fingerprint.
//
// The lock screen never says a wipe is happening. The duress PIN and the wrong-PIN limit show
// the same "checking" state as any attempt while DesktopAppLock.wipe runs, then the app closes
// and opens again as a fresh install.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.lock.PinCheck
import com.pgpony.android.lock.PinFormat
import com.pgpony.android.lock.PinRules
import com.pgpony.android.lock.PinSetup
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Keep digits only, up to the longest PIN. */
private fun digitsOnly(s: String): String = s.filter { it in '0'..'9' }.take(PinRules.MAX_LENGTH)

/** Submit on Enter. */
private fun Modifier.onEnter(action: () -> Unit): Modifier = onPreviewKeyEvent {
    if (it.type == KeyEventType.KeyDown && (it.key == Key.Enter || it.key == Key.NumPadEnter)) { action(); true } else false
}

// ── The lock screen ────────────────────────────────────────────────────

@Composable
fun AppLockScreen(state: DesktopState) {
    var pin by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var waitUntilMs by remember { mutableStateOf(0L) }
    var waitSeconds by remember { mutableIntStateOf(0) }
    var unavailable by remember { mutableStateOf(false) }
    var confirmReset by remember { mutableStateOf(false) }
    val focus = remember { FocusRequester() }

    // A delay already running (wrong PINs before this launch) shows at once.
    LaunchedEffect(Unit) {
        val config = DesktopAppLock.load()
        if (config == null) unavailable = true
        else {
            unavailable = false
            val remaining = DesktopAppLock.throttleRemainingMs(config)
            if (remaining > 0) waitUntilMs = System.currentTimeMillis() + remaining
        }
        runCatching { focus.requestFocus() }
    }
    LaunchedEffect(waitUntilMs) {
        while (true) {
            val left = waitUntilMs - System.currentTimeMillis()
            if (left <= 0) { waitSeconds = 0; break }
            waitSeconds = ((left + 999) / 1000).toInt()
            delay(250)
        }
    }

    fun submit() {
        if (pin.isEmpty() || working || waitSeconds > 0) return
        val entered = pin
        pin = ""
        working = true
        error = null
        DesktopAppLock.scope.launch {
            val outcome = runCatching { DesktopAppLock.submit(entered) }.getOrElse { null }
            when (outcome) {
                PinCheck.Unlocked -> working = false
                PinCheck.Duress, is PinCheck.WipeLimit -> {
                    // Silent: the screen stays on "checking" until the app restarts fresh.
                    DesktopAppLock.wipe(state.edits)
                    DesktopAppLock.relaunchFresh()
                }
                is PinCheck.Wrong -> {
                    working = false
                    error = tr("applock_wrong_pin")
                    if (outcome.delayMs > 0) waitUntilMs = System.currentTimeMillis() + outcome.delayMs
                }
                is PinCheck.Throttled -> {
                    working = false
                    waitUntilMs = System.currentTimeMillis() + outcome.remainingMs
                }
                PinCheck.Unsupported -> { working = false; unavailable = true }
                null -> { working = false; error = tr("applock_check_failed") }
            }
        }
    }

    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Column(
                Modifier.widthIn(max = 360.dp).padding(Spacing.Section),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                BrandMark(size = 72.dp)
                Spacer(Modifier.height(Spacing.Large))
                Text(
                    tr("applock_verify_title"),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(Modifier.height(Spacing.Large))
                if (unavailable) {
                    Text(tr("applock_unavailable"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                    Spacer(Modifier.height(Spacing.Medium))
                    OutlinedButton(onClick = { confirmReset = true }) { Text(tr("applock_reset_button")) }
                } else {
                    OutlinedTextField(
                        value = pin,
                        onValueChange = { pin = digitsOnly(it); error = null },
                        singleLine = true,
                        enabled = !working && waitSeconds == 0,
                        label = { Text(tr("applock_pin_field_label")) },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.fillMaxWidth().focusRequester(focus).onEnter { submit() }
                    )
                    Spacer(Modifier.height(Spacing.Medium))
                    BrandButton(
                        onClick = { submit() },
                        enabled = pin.isNotEmpty() && !working && waitSeconds == 0,
                        modifier = Modifier.fillMaxWidth()
                    ) { Text(if (working) tr("d_common_working") else tr("d_applock_unlock")) }
                    val line = when {
                        waitSeconds > 0 -> tr("applock_wait_format", waitSeconds)
                        else -> error
                    }
                    if (line != null) {
                        Spacer(Modifier.height(Spacing.Medium))
                        Text(line, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }

    if (confirmReset) {
        BrandDialog(
            onDismissRequest = { confirmReset = false },
            title = tr("applock_reset_confirm_title"),
            destructive = true,
            content = { Text(tr("applock_reset_confirm_message")) },
            confirmButton = {
                TextButton(onClick = {
                    confirmReset = false
                    working = true
                    DesktopAppLock.scope.launch {
                        DesktopAppLock.wipe(state.edits)
                        DesktopAppLock.relaunchFresh()
                    }
                }) { Text(tr("applock_reset_confirm_button"), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmReset = false }) { Text(tr("common_button_cancel")) } }
        )
    }
}

// ── Settings ───────────────────────────────────────────────────────────

/** What a verified PIN is about to be used for in Settings. */
private enum class LockAction { CHANGE_PIN, TURN_OFF, SET_DURESS, REMOVE_DURESS, WIPE_AFTER }

@Composable
fun AppLockSection(state: DesktopState) {
    val scope = rememberCoroutineScope()
    var isSet by remember { mutableStateOf(DesktopAppLock.isSet()) }
    var hasDuress by remember { mutableStateOf(false) }
    var wipeAfter by remember { mutableIntStateOf(0) }
    var idle by remember { mutableIntStateOf(DesktopAppLock.idleMinutes()) }
    var refreshTick by remember { mutableIntStateOf(0) }
    // Android's rule: Settings asks for the PIN once per visit, and again after every lock.
    var verifiedEpoch by remember { mutableIntStateOf(-1) }

    var creating by remember { mutableStateOf(false) }
    var pendingAction by remember { mutableStateOf<LockAction?>(null) }
    var verifying by remember { mutableStateOf(false) }
    var action by remember { mutableStateOf<LockAction?>(null) }
    var pendingWipeAfter by remember { mutableIntStateOf(0) }
    var wipeMenu by remember { mutableStateOf(false) }
    var idleMenu by remember { mutableStateOf(false) }

    LaunchedEffect(refreshTick, isSet) {
        val c = if (isSet) DesktopAppLock.load() else null
        hasDuress = c?.hasDuress == true
        wipeAfter = c?.wipeAfter ?: 0
    }

    fun request(a: LockAction) {
        if (verifiedEpoch == DesktopAppLock.lockEpoch) action = a
        else { pendingAction = a; verifying = true }
    }

    if (!isSet) {
        Text(tr("d_applock_off_note"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(Spacing.Medium))
        OutlinedButton(onClick = { creating = true }) { Text(tr("applock_set_pin_title")) }
    } else {
        LabeledValue(label = tr("applock_method_pin"), value = tr("applock_duress_on"))
        Spacer(Modifier.height(Spacing.Small))
        WrapRow(horizontalSpacing = Spacing.Small, verticalSpacing = Spacing.Small) {
            OutlinedButton(onClick = { DesktopAppLock.lockNow() }) { Text(tr("d_applock_lock_now")) }
            OutlinedButton(onClick = { request(LockAction.CHANGE_PIN) }) { Text(tr("applock_change_pin_title")) }
            TextButton(onClick = { request(LockAction.TURN_OFF) }) { Text(tr("d_applock_turn_off")) }
        }

        Spacer(Modifier.height(Spacing.Large))
        LabeledValue(label = tr("applock_duress_title"), value = tr(if (hasDuress) "applock_duress_on" else "applock_duress_off"))
        Spacer(Modifier.height(Spacing.Small))
        Row(horizontalArrangement = Arrangement.spacedBy(Spacing.Small)) {
            OutlinedButton(onClick = { request(LockAction.SET_DURESS) }) {
                Text(if (hasDuress) tr("applock_duress_set_title") else tr("applock_duress_info_title"))
            }
            if (hasDuress) TextButton(onClick = { request(LockAction.REMOVE_DURESS) }) { Text(tr("applock_duress_remove_button")) }
        }

        Spacer(Modifier.height(Spacing.Large))
        Text(tr("applock_wipe_after_title"), style = MaterialTheme.typography.titleSmall)
        Text(tr("applock_wipe_after_message"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(Spacing.Small))
        Box {
            OutlinedButton(onClick = { wipeMenu = true }) {
                Text(if (wipeAfter == 0) tr("applock_wipe_after_off") else tr("applock_wipe_after_format", wipeAfter))
            }
            DropdownMenu(expanded = wipeMenu, onDismissRequest = { wipeMenu = false }) {
                PinRules.WIPE_AFTER_CHOICES.forEach { n ->
                    DropdownMenuItem(
                        text = { Text(if (n == 0) tr("applock_wipe_after_off") else tr("applock_wipe_after_format", n)) },
                        onClick = { wipeMenu = false; if (n != wipeAfter) { pendingWipeAfter = n; request(LockAction.WIPE_AFTER) } }
                    )
                }
            }
        }

        Spacer(Modifier.height(Spacing.Large))
        Text(tr("d_applock_idle_title"), style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(Spacing.Small))
        Box {
            OutlinedButton(onClick = { idleMenu = true }) { Text(idleLabel(idle)) }
            DropdownMenu(expanded = idleMenu, onDismissRequest = { idleMenu = false }) {
                DesktopAppLock.IDLE_CHOICES.forEach { m ->
                    DropdownMenuItem(text = { Text(idleLabel(m)) }, onClick = {
                        idleMenu = false; DesktopAppLock.setIdleMinutes(m); idle = m
                    })
                }
            }
        }
    }

    if (creating) {
        PinEntryDialog(
            title = tr("applock_set_pin_title"),
            message = tr("applock_set_pin_message"),
            onDismiss = { creating = false },
            run = { pin -> DesktopAppLock.create(pin) },
            onDone = { creating = false; isSet = true; verifiedEpoch = DesktopAppLock.lockEpoch; refreshTick++ }
        )
    }

    if (verifying) {
        VerifyPinDialog(
            state = state,
            onDismiss = { verifying = false; pendingAction = null },
            onVerified = {
                verifying = false
                verifiedEpoch = DesktopAppLock.lockEpoch
                action = pendingAction
                pendingAction = null
            }
        )
    }

    when (action) {
        LockAction.CHANGE_PIN -> PinEntryDialog(
            title = tr("applock_change_pin_title"),
            message = tr("applock_change_pin_subtitle"),
            onDismiss = { action = null },
            run = { pin -> DesktopAppLock.changePin(pin) },
            onDone = { action = null; refreshTick++ }
        )
        LockAction.SET_DURESS -> DuressSetupFlow(
            onDismiss = { action = null },
            onDone = { action = null; refreshTick++ }
        )
        LockAction.REMOVE_DURESS -> BrandDialog(
            onDismissRequest = { action = null },
            title = tr("applock_duress_remove_title"),
            content = { Text(tr("applock_duress_remove_message")) },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch { DesktopAppLock.removeDuress(); action = null; refreshTick++ }
                }) { Text(tr("applock_duress_remove_button")) }
            },
            dismissButton = { TextButton(onClick = { action = null }) { Text(tr("common_button_cancel")) } }
        )
        LockAction.TURN_OFF -> BrandDialog(
            onDismissRequest = { action = null },
            title = tr("d_applock_turn_off_title"),
            content = { Text(tr("d_applock_turn_off_message")) },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch { DesktopAppLock.turnOff(); action = null; isSet = false; refreshTick++ }
                }) { Text(tr("d_applock_turn_off")) }
            },
            dismissButton = { TextButton(onClick = { action = null }) { Text(tr("common_button_cancel")) } }
        )
        LockAction.WIPE_AFTER -> LaunchedEffect(Unit) {
            DesktopAppLock.setWipeAfter(pendingWipeAfter)
            action = null
            refreshTick++
        }
        null -> {}
    }
}

private fun idleLabel(minutes: Int): String =
    if (minutes == 0) tr("d_applock_idle_never") else trQuantity("d_applock_idle_minutes", minutes)

/** Ask for the current PIN. The duress PIN here wipes, the same as on the lock screen. */
@Composable
private fun VerifyPinDialog(state: DesktopState, onDismiss: () -> Unit, onVerified: () -> Unit) {
    var pin by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun submit() {
        if (pin.isEmpty() || working) return
        val entered = pin
        pin = ""
        working = true
        error = null
        DesktopAppLock.scope.launch {
            when (val r = runCatching { DesktopAppLock.submit(entered) }.getOrNull()) {
                PinCheck.Unlocked -> { working = false; onVerified() }
                PinCheck.Duress, is PinCheck.WipeLimit -> {
                    DesktopAppLock.wipe(state.edits)
                    DesktopAppLock.relaunchFresh()
                }
                is PinCheck.Wrong -> { working = false; error = tr("applock_wrong_pin") }
                is PinCheck.Throttled -> { working = false; error = tr("applock_wait_format", ((r.remainingMs + 999) / 1000).toInt()) }
                PinCheck.Unsupported -> { working = false; error = tr("applock_unavailable") }
                null -> { working = false; error = tr("applock_check_failed") }
            }
        }
    }

    BrandDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = tr("applock_verify_title"),
        content = {
            Column(Modifier.fillMaxWidth()) {
                Text(tr("applock_verify_message"), style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(Spacing.Medium))
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = digitsOnly(it); error = null },
                    singleLine = true,
                    enabled = !working,
                    label = { Text(tr("applock_pin_field_label")) },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth().onEnter { submit() }
                )
                error?.let {
                    Spacer(Modifier.height(Spacing.Small))
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = pin.isNotEmpty() && !working, onClick = { submit() }) {
                Text(if (working) tr("d_common_working") else tr("common_button_continue"))
            }
        },
        dismissButton = { TextButton(enabled = !working, onClick = onDismiss) { Text(tr("common_button_cancel")) } }
    )
}

/** A new PIN, typed twice. [run] sets it; a result other than Done shows its reason. */
@Composable
private fun PinEntryDialog(
    title: String,
    message: String,
    onDismiss: () -> Unit,
    run: suspend (String) -> PinSetup,
    onDone: () -> Unit,
    sameAsOtherKey: String = "applock_pin_same_as_duress",
    extra: @Composable () -> Unit = {}
) {
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun submit() {
        if (working) return
        if (PinRules.check(pin) != PinFormat.OK) { error = tr("applock_pin_format_error"); return }
        if (pin != confirm) { error = tr("applock_pin_mismatch"); return }
        working = true
        error = null
        val entered = pin
        scope.launch {
            val r = runCatching { run(entered) }.getOrNull()
            working = false
            when (r) {
                is PinSetup.Done -> onDone()
                is PinSetup.Invalid -> error = tr("applock_pin_format_error")
                PinSetup.SameAsOther -> error = tr(sameAsOtherKey)
                PinSetup.Unsupported, null -> error = tr("applock_check_failed")
            }
        }
    }

    BrandDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = title,
        content = {
            Column(Modifier.fillMaxWidth()) {
                Text(message, style = MaterialTheme.typography.bodyMedium)
                extra()
                Spacer(Modifier.height(Spacing.Medium))
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = digitsOnly(it); error = null },
                    singleLine = true,
                    enabled = !working,
                    label = { Text(tr("applock_new_pin_label")) },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(Spacing.Small))
                OutlinedTextField(
                    value = confirm,
                    onValueChange = { confirm = digitsOnly(it); error = null },
                    singleLine = true,
                    enabled = !working,
                    label = { Text(tr("applock_pin_confirm_label")) },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth().onEnter { submit() }
                )
                error?.let {
                    Spacer(Modifier.height(Spacing.Small))
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = pin.isNotEmpty() && confirm.isNotEmpty() && !working, onClick = { submit() }) {
                Text(if (working) tr("d_common_working") else tr("common_button_save"))
            }
        },
        dismissButton = { TextButton(enabled = !working, onClick = onDismiss) { Text(tr("common_button_cancel")) } }
    )
}

/** The duress PIN: what it does and what it cannot reach first, then the PIN itself. */
@Composable
private fun DuressSetupFlow(onDismiss: () -> Unit, onDone: () -> Unit) {
    var understood by remember { mutableStateOf(false) }
    if (!understood) {
        BrandDialog(
            onDismissRequest = onDismiss,
            title = tr("applock_duress_info_title"),
            destructive = true,
            content = {
                Column {
                    Text(tr("applock_duress_info_message"), style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(Spacing.Medium))
                    Text(tr("d_applock_not_touched"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(Spacing.Small))
                    Text(tr("d_applock_disk_note"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            },
            confirmButton = { TextButton(onClick = { understood = true }) { Text(tr("common_button_continue")) } },
            dismissButton = { TextButton(onClick = onDismiss) { Text(tr("common_button_cancel")) } }
        )
    } else {
        PinEntryDialog(
            title = tr("applock_duress_set_title"),
            message = tr("applock_set_pin_message"),
            onDismiss = onDismiss,
            run = { pin -> DesktopAppLock.setDuress(pin) },
            onDone = onDone,
            sameAsOtherKey = "applock_duress_same_as_pin"
        )
    }
}
