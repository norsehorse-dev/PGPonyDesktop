// CardsScreen.kt
// PGPony Desktop — D7: the Hardware Keys surface. USB PC/SC counterpart of Android's card
// screens (scan + CardManagementScreen): reader discovery, card read (SELECT + Application
// Related Data → CardInfo), pair/link into the keyring (the A1 offline-primary rule lives in
// the repository), PW1/PW3 lifecycle (change, unblock, factory reset), on-card key
// generation (Ed25519 + Cv25519 — DESTRUCTIVE, keys never leave the card), and the PW1 cache
// controls (TTL picker + live countdown + clear, the 3.1.0 B1/B2 semantics via the vendored
// session's verify() chokepoint).
//
// D11b - LOCALIZATION. Android ships the same card surface across four screens (scan,
// CardManagementScreen, the PIN-change flow, on-card keygen), so thirty-three strings here are
// ANDROID keys reused verbatim - card_scan_slot_*, card_mgmt_done_*, card_keygen_field_*,
// settings_card_pin_cache_* and friends - already translated into five languages. A `d_cards_*`
// key is minted only where the desktop says something the phone doesn't: the USB/PC-SC reader
// row (the phone taps NFC instead), the pairing note, the min-length PIN hints, and the
// desktop's own wording of the two destructive warnings.
//
// Two things worth knowing before editing:
//   - The slot-name keys are chosen by a `when (slot.slot)` inside tr(...), so the
//     everyKeyReferencedInSourceResolves test's regex cannot see them (it requires a quote
//     immediately after `tr(`). card_scan_slot_signature / _decryption / _authentication are
//     verified by hand instead. Same for the expiry radio labels, which are fine because the
//     literals sit right there in the argument list.
//   - CACHE_CHOICES used to be a top-level `private val` holding resolved English. A top-level
//     val initializes once per process, which would freeze those five labels in whatever
//     language was active at class-load time. It now lives inside PinCacheSection().

package com.pgpony.desktop

import androidx.compose.foundation.background
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.crypto.card.CardInfo
import com.pgpony.android.crypto.card.CardKeygenService
import com.pgpony.android.crypto.card.CardPinCache
import com.pgpony.android.crypto.card.CardSlot
import com.pgpony.android.crypto.card.OpenPgpCardSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private enum class CardDialog { NONE, CHANGE_PIN, CHANGE_ADMIN, UNBLOCK, FACTORY_RESET, KEYGEN, MOVE_KEY }

@Composable
fun CardsScreen(state: DesktopState) {
    val scope = rememberCoroutineScope()
    var readers by remember { mutableStateOf(DesktopCardReader.listReaders()) }
    var reader by remember {
        mutableStateOf(readers.firstOrNull { it.cardPresent }?.name ?: readers.firstOrNull()?.name)
    }
    var readerMenu by remember { mutableStateOf(false) }
    var info by remember { mutableStateOf<CardInfo?>(null) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var messageIsError by remember { mutableStateOf(false) }
    var dialog by remember { mutableStateOf(CardDialog.NONE) }

    /** Run one card operation on the selected reader with busy/message handling. */
    fun op(doneMsg: String?, rereadInfo: Boolean = false, operation: (OpenPgpCardSession) -> Unit) {
        busy = true
        message = null
        scope.launch {
            try {
                val newInfo = withContext(Dispatchers.IO) {
                    DesktopCardReader.withCard(reader) { session ->
                        operation(session)
                        if (rereadInfo) {
                            session.select()
                            session.readCardInfo()
                        } else null
                    }
                }
                if (newInfo != null) info = newInfo
                doneMsg?.let { message = it; messageIsError = false }
            } catch (t: Throwable) {
                message = t.message ?: t::class.simpleName
                messageIsError = true
            } finally {
                busy = false
            }
        }
    }

    fun rescan() {
        readers = DesktopCardReader.listReaders()
        if (reader !in readers.map { it.name }) {
            reader = readers.firstOrNull { it.cardPresent }?.name ?: readers.firstOrNull()?.name
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(Spacing.Section)
            .verticalScroll(rememberScrollState())
    ) {
        ScreenHeader(title = tr("d_nav_cards"), subtitle = tr("d_cards_subtitle"))
        Spacer(Modifier.height(Spacing.Section))

        // ── Reader ──────────────────────────────────────────────────────
        SectionCard(tr("d_cards_section_reader")) {
            WrapRow(verticalSpacing = Spacing.Medium) {
                Text(tr("d_cards_reader_label"), style = MaterialTheme.typography.bodyMedium)
                // Boxed with its anchor: a bare DropdownMenu sibling would be packed as its own
                // WrapRow item and measure to nothing, desynchronising the gaps (D12 batch 1).
                Box {
                    OutlinedButton(
                        onClick = { readerMenu = true },
                        enabled = !busy && readers.isNotEmpty(),
                        shape = RoundedCornerShape(Radius.Small)
                    ) {
                        Text(reader ?: tr("d_cards_no_reader"))
                    }
                    DropdownMenu(expanded = readerMenu, onDismissRequest = { readerMenu = false }) {
                        readers.forEach { r ->
                            DropdownMenuItem(
                                text = {
                                    Text(if (r.cardPresent) tr("d_cards_reader_with_card", r.name) else r.name)
                                },
                                onClick = { reader = r.name; readerMenu = false }
                            )
                        }
                    }
                }
                OutlinedButton(
                    onClick = { rescan() },
                    enabled = !busy,
                    shape = RoundedCornerShape(Radius.Small)
                ) { Text(tr("d_pass_rescan")) }
                BrandButton(
                    enabled = !busy && readers.isNotEmpty(),
                    onClick = {
                        op(doneMsg = null, rereadInfo = true) { session ->
                            session.select()
                            // rereadInfo does the actual read; this op just proves the AID.
                        }
                    }
                ) { Text(if (busy) tr("d_common_working") else tr("d_cards_read_card")) }
            }
        }

        message?.let {
            Spacer(Modifier.height(Spacing.Medium))
            StatusStrip(it, error = messageIsError)
        }

        Spacer(Modifier.height(Spacing.Large))

        // ── The card, or why there isn't one ────────────────────────────
        //
        // No fillMaxSize on these EmptyStates: this column scrolls, so its children are measured
        // with an unbounded height and a fill modifier would resolve to zero.
        //
        // `info` is a Compose-delegated var and cannot be smart-cast, so it is read once into a
        // local. That also means every branch below sees the same snapshot value.
        val card = info
        when {
            readers.isEmpty() -> EmptyState(
                icon = Icons.Filled.Usb,
                title = tr("d_cards_no_reader_title"),
                message = listOfNotNull(
                    tr("d_cards_no_reader_detected"),
                    // When PC/SC failed for a REASON — service not running, reader held by another
                    // program — say that reason in plain words. "Nothing is plugged in" and "the
                    // service is not running" are the same empty list to every caller but
                    // completely different problems, and the second is unfixable by plugging
                    // something in. The raw SCARD chain stays in `pgpony card-info`, not here
                    // (D19 — a tester's screenshot caught it leaking to users).
                    friendlyPcscReason(DesktopCardReader.lastListError),
                    tr("d_cards_no_reader_linux").takeIf {
                        System.getProperty("os.name").lowercase().contains("linux")
                    }
                ).joinToString(" ")
            ) {
                OutlinedButton(onClick = { rescan() }, enabled = !busy) { Text(tr("d_pass_rescan")) }
            }

            card == null -> EmptyState(
                icon = Icons.Filled.CreditCard,
                title = tr("d_cards_no_card_title"),
                message = tr("d_cards_no_card_body")
            ) {
                BrandButton(
                    enabled = !busy,
                    onClick = {
                        op(doneMsg = null, rereadInfo = true) { session -> session.select() }
                    }
                ) { Text(if (busy) tr("d_common_working") else tr("d_cards_read_card")) }
            }

            else -> {
                CardPanel(card)
                Spacer(Modifier.height(Spacing.Large))
                WrapRow {
                    BrandButton(
                        enabled = !busy && card.hasAnyKey,
                        onClick = {
                            busy = true
                            scope.launch {
                                try {
                                    val entity = state.repository.importCardKey(card)
                                    state.reload()
                                    message = tr(
                                        "d_cards_paired",
                                        entity.userID.ifBlank { entity.shortFingerprint }
                                    )
                                    messageIsError = false
                                } catch (t: Throwable) {
                                    message = t.message ?: t::class.simpleName
                                    messageIsError = true
                                } finally {
                                    busy = false
                                }
                            }
                        }
                    ) { Text(tr("d_cards_pair")) }
                    OutlinedButton(
                        enabled = !busy,
                        onClick = { dialog = CardDialog.KEYGEN },
                        shape = RoundedCornerShape(Radius.Small)
                    ) {
                        Text(tr("d_cards_keygen_open"))
                    }
                    OutlinedButton(
                        enabled = !busy,
                        onClick = { dialog = CardDialog.MOVE_KEY },
                        shape = RoundedCornerShape(Radius.Small)
                    ) {
                        Text(tr("d_cards_move_open"))
                    }
                }
                Spacer(Modifier.height(Spacing.Small))
                Text(
                    tr("d_cards_pair_note"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // ── Management ──────────────────────────────────────────────────
        Spacer(Modifier.height(Spacing.Large))
        SectionCard(tr("card_mgmt_title")) {
            WrapRow {
                OutlinedButton(enabled = !busy && readers.isNotEmpty(),
                    shape = RoundedCornerShape(Radius.Small),
                    onClick = { dialog = CardDialog.CHANGE_PIN }) { Text(tr("d_cards_change_pin_open")) }
                OutlinedButton(enabled = !busy && readers.isNotEmpty(),
                    shape = RoundedCornerShape(Radius.Small),
                    onClick = { dialog = CardDialog.CHANGE_ADMIN }) { Text(tr("d_cards_change_admin_open")) }
                OutlinedButton(enabled = !busy && readers.isNotEmpty(),
                    shape = RoundedCornerShape(Radius.Small),
                    onClick = { dialog = CardDialog.UNBLOCK }) { Text(tr("d_cards_unblock_open")) }
                OutlinedButton(enabled = !busy && readers.isNotEmpty(),
                    shape = RoundedCornerShape(Radius.Small),
                    onClick = { dialog = CardDialog.FACTORY_RESET }) {
                    Text(tr("d_cards_reset_open"), color = MaterialTheme.colorScheme.error)
                }
            }
        }

        // ── PIN cache ───────────────────────────────────────────────────
        Spacer(Modifier.height(Spacing.Large))
        SectionCard(tr("d_cards_pin_cache_title")) {
            PinCacheSection()
        }
        Spacer(Modifier.height(Spacing.Medium))
    }

    // ── Dialogs ─────────────────────────────────────────────────────────
    when (dialog) {
        CardDialog.CHANGE_PIN -> TwoPinDialog(
            title = tr("card_pin_change_title"),
            firstLabel = tr("card_pin_change_current_label"),
            secondLabel = tr("d_cards_new_pin_min6"),
            confirmSecond = true,
            minSecondLen = 6,
            busy = busy,
            onDismiss = { dialog = CardDialog.NONE },
            onSubmit = { old, new ->
                dialog = CardDialog.NONE
                op(tr("card_pin_change_success")) { s -> s.changeUserPin(old, new) }
            }
        )
        CardDialog.CHANGE_ADMIN -> TwoPinDialog(
            title = tr("card_mgmt_action_change_admin"),
            firstLabel = tr("card_mgmt_field_current_admin"),
            secondLabel = tr("d_cards_new_admin_min8"),
            confirmSecond = true,
            minSecondLen = 8,
            busy = busy,
            onDismiss = { dialog = CardDialog.NONE },
            onSubmit = { old, new ->
                dialog = CardDialog.NONE
                op(tr("card_mgmt_done_admin")) { s -> s.changeAdminPin(old, new) }
            }
        )
        CardDialog.UNBLOCK -> TwoPinDialog(
            title = tr("card_mgmt_action_unblock"),
            firstLabel = tr("card_keygen_field_admin_pin"),
            secondLabel = tr("d_cards_new_user_pin_min6"),
            confirmSecond = true,
            minSecondLen = 6,
            busy = busy,
            onDismiss = { dialog = CardDialog.NONE },
            onSubmit = { admin, new ->
                dialog = CardDialog.NONE
                op(tr("card_mgmt_done_unblock"), rereadInfo = true) { s -> s.unblockUserPin(admin, new) }
            }
        )
        CardDialog.FACTORY_RESET -> FactoryResetDialog(
            busy = busy,
            onDismiss = { dialog = CardDialog.NONE },
            onConfirm = {
                dialog = CardDialog.NONE
                op(tr("card_mgmt_done_reset"), rereadInfo = true) { s -> s.factoryReset() }
            }
        )
        CardDialog.KEYGEN -> CardKeygenDialog(
            busy = busy,
            onDismiss = { dialog = CardDialog.NONE },
            onGenerate = { algo, name, email, expirationSeconds, adminPin, userPin ->
                dialog = CardDialog.NONE
                busy = true
                message = null
                scope.launch {
                    try {
                        val result = withContext(Dispatchers.IO) {
                            DesktopCardReader.withCard(reader) { session ->
                                when (algo) {
                                    CardKeyAlgo.ED25519 -> CardKeygenService.generateOnCard(
                                        session, name, email, expirationSeconds, adminPin, userPin
                                    )
                                    CardKeyAlgo.RSA_2048 -> DesktopCardKeygen.generateRsaOnCard(
                                        session, DesktopCardKeygen.RsaBits.RSA_2048,
                                        name, email, expirationSeconds, adminPin, userPin
                                    )
                                    CardKeyAlgo.RSA_4096 -> DesktopCardKeygen.generateRsaOnCard(
                                        session, DesktopCardKeygen.RsaBits.RSA_4096,
                                        name, email, expirationSeconds, adminPin, userPin
                                    )
                                }
                            }
                        }
                        val entity = state.repository.importGeneratedCardKey(
                            result.publicKeyBinary, result.cardInfo
                        )
                        info = result.cardInfo
                        state.reload()
                        message = tr(
                            "d_cards_keygen_done",
                            entity.userID.ifBlank { entity.shortFingerprint }
                        )
                        messageIsError = false
                    } catch (t: Throwable) {
                        message = t.message ?: t::class.simpleName
                        messageIsError = true
                    } finally {
                        busy = false
                    }
                }
            }
        )
        CardDialog.MOVE_KEY -> MoveKeyToCardDialog(
            busy = busy,
            candidates = state.keys.filter { it.isKeyPair && !it.isRevoked && it.algorithm.name.startsWith("RSA") },
            onDismiss = { dialog = CardDialog.NONE },
            onMove = { fingerprint, passphrase, adminPin, format ->
                dialog = CardDialog.NONE
                busy = true
                message = null
                scope.launch {
                    try {
                        val ring = state.repository.loadSecretKeyRing(fingerprint)
                            ?: error(tr("d_cards_move_no_secret"))
                        val result = withContext(Dispatchers.IO) {
                            DesktopCardReader.withCardTransport(reader) { transport ->
                                DesktopCardKeyImport.moveToCard(transport, ring, passphrase, adminPin, format)
                            }
                        }
                        val entity = state.repository.importCardKey(result.cardInfo)
                        info = result.cardInfo
                        state.reload()
                        message = tr("d_cards_move_done", entity.userID.ifBlank { entity.shortFingerprint })
                        messageIsError = false
                    } catch (t: Throwable) {
                        message = t.message ?: t::class.simpleName
                        messageIsError = true
                    } finally {
                        busy = false
                    }
                }
            }
        )
        CardDialog.NONE -> Unit
    }
}

// ── The card itself ────────────────────────────────────────────────────
//
// D12 — one BrandCard carrying the mark, the AID, the three slots and the retry counters. The
// slot rows used to be a fixed 120dp label beside an unbounded Column, which clipped the German
// "Authentifizierung" and left the algorithm hanging. They are WrapRows now, with the algorithm
// as a badge so the eye can find "which slots are populated" without reading three fingerprints.

@Composable
private fun CardPanel(card: CardInfo) {
    BrandCard(Modifier.fillMaxWidth()) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(44.dp)
                        .clip(RoundedCornerShape(Radius.Medium))
                        .background(Brand.gradient()),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Filled.CreditCard,
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(22.dp)
                    )
                }
                Spacer(Modifier.width(Spacing.Medium))
                Column {
                    Text(
                        card.displayName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        tr("d_cards_aid", card.aidHex),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Spacer(Modifier.height(Spacing.Large))
            BrandRule()
            Spacer(Modifier.height(Spacing.Medium))

            card.slots.forEachIndexed { index, slot ->
                if (index > 0) Spacer(Modifier.height(Spacing.Medium))
                Text(
                    tr(
                        when (slot.slot) {
                            CardSlot.SIGNATURE -> "card_scan_slot_signature"
                            CardSlot.DECRYPTION -> "card_scan_slot_decryption"
                            CardSlot.AUTHENTICATION -> "card_scan_slot_authentication"
                        }
                    ),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(Modifier.height(Spacing.Tight))
                if (slot.hasKey) {
                    WrapRow(horizontalSpacing = Spacing.Small, verticalSpacing = Spacing.Tight) {
                        BrandBadge(slot.displayAlgorithm, BadgeTone.Brand)
                        Text(
                            slot.fingerprint!!.uppercase().chunked(4).joinToString(" "),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    slot.generationTime?.let {
                        Spacer(Modifier.height(Spacing.Tight))
                        Text(
                            tr(
                                "card_scan_slot_generated",
                                CARD_DATE.format(
                                    Instant.ofEpochMilli(it).atZone(ZoneId.systemDefault())
                                )
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                } else {
                    BrandBadge(tr("card_scan_slot_empty"))
                }
            }

            Spacer(Modifier.height(Spacing.Large))
            // Low retry counters are the one number on this screen that can cost someone their
            // card, so they get the error tone rather than a colour swap on body copy.
            val lowTries = card.pw1TriesRemaining <= 1 || card.pw3TriesRemaining <= 1
            BrandBadge(
                tr("d_cards_pin_tries", card.pw1TriesRemaining, card.pw3TriesRemaining),
                if (lowTries) BadgeTone.Error else BadgeTone.Neutral
            )
        }
    }
}

// ── PIN cache section ──────────────────────────────────────────────────

@Composable
private fun PinCacheSection() {
    // Built here rather than as a top-level val: a top-level val initializes once per process,
    // which would freeze these five labels in whatever language was active at class-load time.
    val cacheChoices = listOf(
        60 to tr("settings_card_pin_cache_1min"),
        300 to tr("settings_card_pin_cache_5min"),
        900 to tr("settings_card_pin_cache_15min"),
        3600 to tr("settings_card_pin_cache_1hr"),
        CardPinCache.DURATION_UNTIL_CLEARED to tr("settings_card_pin_cache_until_cleared")
    )
    var version by remember { mutableStateOf(0) }
    val enabled = remember(version) { CardPinCache.isEnabled() }
    val durationSec = remember(version) { CardPinCache.durationSec() }
    var remaining by remember { mutableStateOf(CardPinCache.remainingMs()) }
    var menuOpen by remember { mutableStateOf(false) }

    // Live countdown while a PIN is held.
    LaunchedEffect(version) {
        while (true) {
            remaining = CardPinCache.remainingMs()
            delay(1000)
        }
    }

    // Heading comes from the enclosing SectionCard (D12).
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(
            checked = enabled,
            onCheckedChange = { CardPinCache.setEnabled(it); version++ }
        )
        Text(tr("d_cards_pin_cache_toggle"), style = MaterialTheme.typography.bodyMedium)
    }
    if (enabled) {
        Spacer(Modifier.height(Spacing.Small))
        WrapRow(verticalSpacing = Spacing.Medium) {
            Text(tr("d_cards_pin_cache_keep_for"), style = MaterialTheme.typography.bodyMedium)
            Box {
                OutlinedButton(onClick = { menuOpen = true }, shape = RoundedCornerShape(Radius.Small)) {
                    Text(cacheChoices.firstOrNull { it.first == durationSec }?.second
                        ?: tr("d_cards_pin_cache_custom_seconds", durationSec))
                }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    cacheChoices.forEach { (sec, label) ->
                        DropdownMenuItem(
                            text = { Text(label) },
                            onClick = { CardPinCache.setDurationSec(sec); menuOpen = false; version++ }
                        )
                    }
                }
            }
            if (CardPinCache.isHolding()) {
                BrandBadge(
                    if (CardPinCache.isUntilCleared()) tr("d_cards_pin_held_no_timer")
                    else tr("settings_card_pin_cache_countdown_format", formatCountdown(remaining)),
                    BadgeTone.Brand
                )
                TextButton(onClick = { CardPinCache.clear(); version++ }) { Text(tr("d_common_clear_now")) }
            }
        }
        Spacer(Modifier.height(Spacing.Small))
        Text(
            tr("d_cards_pin_cache_note"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

private fun formatCountdown(ms: Long): String {
    val totalSec = ms / 1000
    return "%d:%02d".format(totalSec / 60, totalSec % 60)
}

// ── Dialogs ────────────────────────────────────────────────────────────

@Composable
private fun TwoPinDialog(
    title: String,
    firstLabel: String,
    secondLabel: String,
    confirmSecond: Boolean,
    minSecondLen: Int,
    busy: Boolean,
    onDismiss: () -> Unit,
    onSubmit: (first: String, second: String) -> Unit
) {
    var first by remember { mutableStateOf("") }
    var second by remember { mutableStateOf("") }
    var secondConfirm by remember { mutableStateOf("") }
    val valid = first.isNotBlank() && second.length >= minSecondLen &&
        (!confirmSecond || second == secondConfirm)

    BrandDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = title,
        content = {
            Column {
                OutlinedTextField(
                    value = first, onValueChange = { first = it },
                    label = { Text(firstLabel) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = second, onValueChange = { second = it },
                    label = { Text(secondLabel) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    isError = second.isNotBlank() && second.length < minSecondLen,
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
                if (confirmSecond) {
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = secondConfirm, onValueChange = { secondConfirm = it },
                        label = { Text(tr("card_mgmt_field_confirm")) }, singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        isError = secondConfirm.isNotBlank() && second != secondConfirm,
                        enabled = !busy, modifier = Modifier.fillMaxWidth()
                    )
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    tr("d_cards_pin_retry_warning"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(enabled = valid && !busy, onClick = { onSubmit(first, second) }) {
                Text(tr("d_common_apply"))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text(tr("common_button_cancel")) } }
    )
}

/** Untranslated sentinel - the user types this exact word whatever the UI language. */
private const val RESET_WORD = "RESET"

@Composable
private fun FactoryResetDialog(busy: Boolean, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    var typed by remember { mutableStateOf("") }
    BrandDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = tr("card_mgmt_action_factory_reset"),
        destructive = true,
        content = {
            Column {
                Text(
                    tr("d_cards_reset_warning"),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = typed, onValueChange = { typed = it },
                    label = { Text(tr("d_cards_reset_type_prompt", RESET_WORD)) }, singleLine = true,
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(enabled = typed == RESET_WORD && !busy, onClick = onConfirm) {
                Text(tr("d_cards_reset_confirm"), color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text(tr("common_button_cancel")) } }
    )
}

/** The on-card key algorithm the dialog offers. Ed25519 goes through the vendored keygen; the
 *  two RSA sizes go through the desktop-owned DesktopCardKeygen (D20). Labels are technical
 *  identifiers, not translated. */
private enum class CardKeyAlgo(val label: String) {
    ED25519("Ed25519"),
    RSA_2048("RSA 2048"),
    RSA_4096("RSA 4096")
}

@Composable
private fun CardKeygenDialog(
    busy: Boolean,
    onDismiss: () -> Unit,
    onGenerate: (algo: CardKeyAlgo, name: String, email: String, expirationSeconds: Long?, adminPin: String, userPin: String) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var algo by remember { mutableStateOf(CardKeyAlgo.ED25519) }
    var years by remember { mutableStateOf(0) }
    var adminPin by remember { mutableStateOf("") }
    var userPin by remember { mutableStateOf("") }
    var confirmed by remember { mutableStateOf(false) }
    val valid = name.isNotBlank() && email.contains("@") &&
        adminPin.isNotBlank() && userPin.isNotBlank() && confirmed

    BrandDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = tr("card_keygen_title"),
        destructive = true,
        content = {
            Column(modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
                Text(
                    tr("d_cards_keygen_warning"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(value = name, onValueChange = { name = it },
                    label = { Text(tr("card_keygen_field_name")) }, singleLine = true,
                    enabled = !busy, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(value = email, onValueChange = { email = it },
                    label = { Text(tr("card_keygen_field_email")) }, singleLine = true,
                    enabled = !busy, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(6.dp))
                Text(tr("d_cards_keygen_algo_label"), style = MaterialTheme.typography.bodyMedium)
                WrapRow {
                    CardKeyAlgo.entries.forEach { a ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(selected = algo == a, onClick = { algo = a }, enabled = !busy)
                            Text(a.label, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
                Spacer(Modifier.height(6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(tr("d_cards_expires_colon"), style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.width(8.dp))
                    listOf(
                        0 to tr("expiration_never"),
                        2 to tr("expiration_two_years"),
                        5 to tr("expiration_five_years")
                    ).forEach { (y, label) ->
                        RadioButton(selected = years == y, onClick = { years = y }, enabled = !busy)
                        Text(label, style = MaterialTheme.typography.bodyMedium)
                    }
                }
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(value = adminPin, onValueChange = { adminPin = it },
                    label = { Text(tr("card_keygen_field_admin_pin")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !busy, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(value = userPin, onValueChange = { userPin = it },
                    label = { Text(tr("card_keygen_field_user_pin")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !busy, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = confirmed, onCheckedChange = { confirmed = it }, enabled = !busy)
                    Text(tr("d_cards_keygen_ack"))
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = valid && !busy,
                onClick = {
                    val expirationSeconds = years.takeIf { it > 0 }?.let { it * 365L * 24 * 60 * 60 }
                    onGenerate(algo, name.trim(), email.trim(), expirationSeconds, adminPin, userPin)
                }
            ) { Text(if (busy) tr("d_common_working") else tr("card_keygen_generate")) }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text(tr("common_button_cancel")) } }
    )
}

/**
 * D21 — move an existing SOFTWARE key onto the card (keytocard). Only RSA keypairs are offered
 * (the first cut); the security trade is stated plainly, because unlike on-card generation this
 * key's secret existed off the card. The import format defaults to CRT and is exposed as a knob,
 * since cards differ on which format they accept for import.
 */
@Composable
private fun MoveKeyToCardDialog(
    busy: Boolean,
    candidates: List<com.pgpony.android.data.PGPKeyEntity>,
    onDismiss: () -> Unit,
    onMove: (fingerprint: String, passphrase: String?, adminPin: String, format: RsaImportFormat) -> Unit
) {
    var selected by remember { mutableStateOf(candidates.firstOrNull()?.fingerprint ?: "") }
    var passphrase by remember { mutableStateOf("") }
    var adminPin by remember { mutableStateOf("") }
    var format by remember { mutableStateOf(RsaImportFormat.CRT) }
    var confirmed by remember { mutableStateOf(false) }
    val valid = selected.isNotBlank() && adminPin.isNotBlank() && confirmed

    BrandDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = tr("d_cards_move_title"),
        destructive = true,
        content = {
            Column(modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
                Text(
                    tr("d_cards_move_warning"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(Modifier.height(8.dp))
                if (candidates.isEmpty()) {
                    Text(tr("d_cards_move_no_candidates"), style = MaterialTheme.typography.bodyMedium)
                } else {
                    Text(tr("d_cards_move_pick_key"), style = MaterialTheme.typography.bodyMedium)
                    candidates.forEach { key ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = selected == key.fingerprint,
                                onClick = { selected = key.fingerprint }, enabled = !busy
                            )
                            Text(
                                key.userID.ifBlank { key.shortFingerprint } + "  (" + key.algorithm.displayName + ")",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(value = passphrase, onValueChange = { passphrase = it },
                    label = { Text(tr("d_cards_move_passphrase")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !busy, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(value = adminPin, onValueChange = { adminPin = it },
                    label = { Text(tr("card_keygen_field_admin_pin")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !busy, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(6.dp))
                Text(tr("d_cards_move_format"), style = MaterialTheme.typography.bodyMedium)
                WrapRow {
                    RsaImportFormat.entries.forEach { f ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(selected = format == f, onClick = { format = f }, enabled = !busy)
                            Text(f.name, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = confirmed, onCheckedChange = { confirmed = it }, enabled = !busy)
                    Text(tr("d_cards_move_ack"))
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = valid && !busy,
                onClick = { onMove(selected, passphrase.ifBlank { null }, adminPin, format) }
            ) { Text(if (busy) tr("d_common_working") else tr("d_cards_move_confirm")) }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text(tr("common_button_cancel")) } }
    )
}

private val CARD_DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd")
