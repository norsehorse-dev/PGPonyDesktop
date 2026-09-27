// KeyDetailManage.kt
// PGPony Desktop 3.0.0, stage 2 (plan 3.3 to 3.8): the Key Detail sections Android grew between
// 4.2.0 and 4.6.0, on top of DesktopKeyEdits. Passphrase set, change or remove; User IDs (add,
// make primary, revoke, remove with a tombstone); subkeys (add classical or post-quantum, revoke,
// remove, the last-encryption-subkey confirmation); notations; decryption fallbacks with strict
// mode; per-key signing defaults. Card-backed keys and public keys show the lists read-only.
//
// Destructive steps (remove User ID, remove subkey) go through DestructiveConfirmDialog and
// disappear with "Hide destructive actions"; revoke always stays.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.FallbackPrefs
import com.pgpony.android.crypto.RevocationError
import com.pgpony.android.crypto.SubkeyCapability
import com.pgpony.android.crypto.UserIdService
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.data.SigningDefaultsEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.openpgp.PGPException
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter

// ── Pure helpers (tested) ──────────────────────────────────────────────

/** One row of the fallback list: a candidate key and whether it is switched on. */
data class FallbackChoice(val key: PGPKeyEntity, val enabled: Boolean)

/** Enabled fallbacks first in their saved order, then the rest of [pool] switched off. */
internal fun fallbackRows(pool: List<PGPKeyEntity>, enabledOrder: List<String>): List<FallbackChoice> {
    val byFp = pool.associateBy { it.fingerprint }
    val rows = mutableListOf<FallbackChoice>()
    enabledOrder.forEach { fp ->
        val k = byFp[fp]
        if (k != null && rows.none { it.key.fingerprint == fp }) rows.add(FallbackChoice(k, true))
    }
    pool.forEach { k -> if (rows.none { it.key.fingerprint == k.fingerprint }) rows.add(FallbackChoice(k, false)) }
    return rows
}

/** Switching on appends to the end of the enabled block; switching off drops to the head of the
 *  disabled block (Android KeyDetailViewModel.toggleFallback). */
internal fun toggleFallback(rows: List<FallbackChoice>, fingerprint: String): List<FallbackChoice> {
    val out = rows.toMutableList()
    val idx = out.indexOfFirst { it.key.fingerprint == fingerprint }
    if (idx < 0) return rows
    val row = out.removeAt(idx)
    val insertAt = out.indexOfFirst { !it.enabled }.let { if (it >= 0) it else out.size }
    out.add(insertAt, row.copy(enabled = !row.enabled))
    return out
}

/** Move an enabled fallback one slot up (-1) or down (+1), within the enabled block. */
internal fun moveFallback(rows: List<FallbackChoice>, fingerprint: String, delta: Int): List<FallbackChoice> {
    val from = rows.indexOfFirst { it.key.fingerprint == fingerprint }
    if (from < 0 || !rows[from].enabled) return rows
    val to = from + delta
    if (to < 0 || to >= rows.size || !rows[to].enabled) return rows
    val out = rows.toMutableList()
    out.add(to, out.removeAt(from))
    return out
}

/** A key-edit failure as the user should read it. Passphrase failures read the same everywhere. */
internal fun editErrorMessage(t: Throwable, fallback: String): String = when (t) {
    is UserIdService.UserIdError.PassphraseRequired,
    is UserIdService.UserIdError.InvalidPassphrase,
    is RevocationError.PassphraseRequired,
    is RevocationError.InvalidPassphrase,
    is PGPException -> tr("encdec_error_incorrect_passphrase_retry")
    else -> t.message?.takeIf { it.isNotBlank() } ?: fallback
}

// ── State ──────────────────────────────────────────────────────────────

private data class ManageData(
    val passphraseProtected: Boolean,
    val userIds: List<DesktopKeyEdits.UserIdRow>,
    val subkeys: List<DesktopKeyEdits.SubkeyRow>,
    val notations: List<UserIdService.Notation>,
    val fallbacks: List<FallbackChoice>,
    val strict: Boolean,
    val defaults: SigningDefaultsEntity
)

private suspend fun loadManageData(state: DesktopState, key: PGPKeyEntity): ManageData {
    val edits = state.edits
    val soft = key.isKeyPair && !key.isCardBacked
    // Android signerChoicePool: software key pairs that are not revoked, this key excluded.
    val pool = if (key.isKeyPair) {
        state.keys.filter { it.isKeyPair && !it.isCardBacked && !it.isRevoked && it.fingerprint != key.fingerprint }
    } else emptyList()
    return ManageData(
        passphraseProtected = soft && runCatching { edits.isPassphraseProtected(key.fingerprint) }.getOrDefault(false),
        userIds = runCatching { edits.userIdRows(key) }.getOrDefault(emptyList()),
        subkeys = runCatching { edits.subkeyRows(key) }.getOrDefault(emptyList()),
        notations = runCatching { edits.readNotations(key.fingerprint) }.getOrDefault(emptyList()),
        fallbacks = if (key.isKeyPair) fallbackRows(pool, edits.fallbacksFor(key.fingerprint)) else emptyList(),
        strict = FallbackPrefs.isStrict(key.fingerprint),
        defaults = edits.signingDefaultsFor(key.fingerprint) ?: SigningDefaultsEntity(key.fingerprint)
    )
}

private sealed class ManageDialog {
    object ChangePassphrase : ManageDialog()
    object AddUserId : ManageDialog()
    class MakePrimary(val uid: String) : ManageDialog()
    class RevokeUserId(val uid: String) : ManageDialog()
    class RemoveUserId(val uid: String) : ManageDialog()
    object AddSubkey : ManageDialog()
    class RevokeSubkey(val row: DesktopKeyEdits.SubkeyRow) : ManageDialog()
    class RemoveSubkey(val row: DesktopKeyEdits.SubkeyRow) : ManageDialog()
    /** Android item 16 (#54): the subkey is the key's last way to receive mail. */
    class LastEncryption(val row: DesktopKeyEdits.SubkeyRow, val revoke: RevokeArgs?) : ManageDialog()
    object Notations : ManageDialog()
}

private class RevokeArgs(val reason: RevocationReason, val comment: String?, val passphrase: String?)

// ── Sections ───────────────────────────────────────────────────────────

/**
 * Everything below the trust and notes block of Key Detail. [primaryInfo] is the primary key's
 * row from DesktopKeyRepository.subkeyInfos (null for a composite key, which BouncyCastle cannot
 * read; the capability line then falls back to the algorithm's usual flags).
 */
@Composable
internal fun KeyManageSections(state: DesktopState, key: PGPKeyEntity, primaryInfo: DesktopKeyRepository.SubkeyInfo?) {
    val scope = rememberCoroutineScope()
    val soft = key.isKeyPair && !key.isCardBacked
    val editable = soft && !key.isRevoked
    val composite = key.algorithm.isCompositeSign
    val hideDestructive = remember { DestructiveGuard.hidden() }
    var data by remember(key.fingerprint) { mutableStateOf<ManageData?>(null) }
    var dialog by remember { mutableStateOf<ManageDialog?>(null) }
    var reload by remember { mutableStateOf(0) }

    LaunchedEffect(key.fingerprint, key.armoredPublicKey, key.lastLocalEditAt, state.keys, reload) {
        data = withContext(Dispatchers.IO) { loadManageData(state, key) }
    }
    val d = data ?: return
    val owner = key.userID.ifBlank { key.shortFingerprint }
    fun closeAndReload() { dialog = null; reload++ }
    fun statusError(fallbackKey: String): (Throwable) -> Unit = { t -> state.status = editErrorMessage(t, tr(fallbackKey)) }

    // ── Passphrase (plan 3.3) ──────────────────────────────────────────
    if (soft) {
        Spacer(Modifier.height(12.dp))
        ManageLabel(tr("d_keydetail_section_passphrase"))
        Text(
            if (d.passphraseProtected) tr("d_keydetail_passphrase_on") else tr("d_keydetail_passphrase_off"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        TextButton(onClick = { dialog = ManageDialog.ChangePassphrase }) { Text(tr("key_detail_action_change_passphrase")) }
    }

    // ── User IDs (plan 3.4) ────────────────────────────────────────────
    Spacer(Modifier.height(12.dp))
    ManageLabel(tr("key_detail_userids_title"))
    d.userIds.forEach { u ->
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 4.dp)) {
            Text(u.raw, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f, fill = false))
            if (u.isPrimary) { Spacer(Modifier.width(6.dp)); ManagePill(tr("key_detail_userids_primary")) }
            if (u.isRevoked) { Spacer(Modifier.width(6.dp)); ManagePill(tr("key_detail_revoked_badge"), error = true) }
        }
        if (editable) {
            WrapRow {
                // Make primary and revoke re-sign through BouncyCastle, which a composite ML-DSA
                // primary is not; Android offers add and remove only on those keys too.
                if (!composite && !u.isPrimary && !u.isRevoked) {
                    TextButton(onClick = { dialog = ManageDialog.MakePrimary(u.raw) }) { Text(tr("key_detail_userids_make_primary")) }
                }
                if (!composite && !u.isRevoked) {
                    TextButton(onClick = { dialog = ManageDialog.RevokeUserId(u.raw) }) { Text(tr("key_detail_userids_revoke")) }
                }
                if (!hideDestructive && d.userIds.size > 1) {
                    TextButton(onClick = { dialog = ManageDialog.RemoveUserId(u.raw) }) {
                        Text(tr("key_detail_userids_remove"), color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }
    if (editable) {
        TextButton(onClick = { dialog = ManageDialog.AddUserId }) { Text(tr("key_detail_userids_add_action")) }
    }

    // ── Keys: primary, then subkeys (plan 3.5) ─────────────────────────
    Spacer(Modifier.height(12.dp))
    ManageLabel(tr("d_keydetail_section_keys", d.subkeys.size + 1))
    KeyRowCard(
        title = tr("key_detail_userids_primary"),
        algorithm = key.algorithm.displayName,
        keyId = key.longKeyId,
        capabilities = primaryInfo?.capabilitiesLabel
            ?: SubkeyCapability.displayString(SubkeyCapability.heuristic(key.algorithm, true)),
        createdAt = key.createdAt,
        expiresAt = key.expiresAt,
        revoked = key.isRevoked
    )
    d.subkeys.forEach { sk ->
        KeyRowCard(
            title = tr("d_keydetail_subkey"),
            algorithm = sk.algorithmLabel,
            keyId = sk.keyId,
            capabilities = SubkeyCapability.displayString(sk.capabilities),
            createdAt = sk.createdAt,
            expiresAt = sk.expiresAt,
            revoked = sk.isRevoked
        ) {
            if (editable && !sk.isRevoked) {
                WrapRow {
                    TextButton(onClick = { dialog = ManageDialog.RevokeSubkey(sk) }) { Text(tr("key_detail_subkey_revoke_action")) }
                    if (!hideDestructive) {
                        TextButton(onClick = { dialog = ManageDialog.RemoveSubkey(sk) }) {
                            Text(tr("key_detail_subkey_remove_action"), color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
        }
    }
    if (editable) {
        TextButton(onClick = { dialog = ManageDialog.AddSubkey }) { Text(tr("key_detail_subkeys_add_action")) }
    }

    // ── Notations (plan 3.6) ───────────────────────────────────────────
    Spacer(Modifier.height(12.dp))
    ManageLabel(tr("key_detail_notations_title"))
    if (d.notations.isEmpty()) {
        Text(tr("key_detail_notations_empty"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    d.notations.forEach { n ->
        Text(tr("d_keydetail_notation_row", n.name, n.value), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
    }
    if (editable && !composite) {
        TextButton(onClick = { dialog = ManageDialog.Notations }) { Text(tr("key_detail_notations_edit_action")) }
    }

    // ── Decryption fallbacks (plan 3.7) ────────────────────────────────
    if (key.isKeyPair) {
        Spacer(Modifier.height(12.dp))
        ManageLabel(tr("key_detail_section_fallbacks"))
        Text(tr("key_detail_fallbacks_explainer"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (d.fallbacks.isEmpty()) {
            Text(tr("key_detail_fallbacks_none"), style = MaterialTheme.typography.bodySmall)
        } else {
            fun persist(rows: List<FallbackChoice>) {
                data = d.copy(fallbacks = rows)
                scope.launch { state.edits.setFallbacks(key.fingerprint, rows.filter { it.enabled }.map { it.key.fingerprint }) }
            }
            val enabledCount = d.fallbacks.count { it.enabled }
            d.fallbacks.forEachIndexed { i, row ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = row.enabled, onCheckedChange = { persist(toggleFallback(d.fallbacks, row.key.fingerprint)) })
                    Text(
                        row.key.userID.ifBlank { row.key.shortFingerprint },
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f)
                    )
                    if (row.enabled) {
                        IconButton(enabled = i > 0, onClick = { persist(moveFallback(d.fallbacks, row.key.fingerprint, -1)) }) {
                            Icon(Icons.Filled.KeyboardArrowUp, contentDescription = tr("key_detail_fallbacks_move_up"))
                        }
                        IconButton(enabled = i < enabledCount - 1, onClick = { persist(moveFallback(d.fallbacks, row.key.fingerprint, 1)) }) {
                            Icon(Icons.Filled.KeyboardArrowDown, contentDescription = tr("key_detail_fallbacks_move_down"))
                        }
                    }
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = d.strict, onCheckedChange = {
                    FallbackPrefs.setStrict(key.fingerprint, it)
                    data = d.copy(strict = it)
                })
                Column {
                    Text(tr("key_detail_fallbacks_strict_title"), style = MaterialTheme.typography.bodyMedium)
                    Text(
                        tr("key_detail_fallbacks_strict_subtitle"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }

    // ── Signing defaults (plan 3.8) ────────────────────────────────────
    if (key.isKeyPair && !key.isRevoked) {
        Spacer(Modifier.height(12.dp))
        ManageLabel(tr("key_detail_section_signing_defaults"))
        Text(tr("key_detail_signing_defaults_explainer"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        val pool = d.fallbacks.map { it.key }
        fun save(slot: Int, fp: String?) {
            val cleaned = fp?.takeIf { it != key.fingerprint }
            val updated = when (slot) {
                0 -> d.defaults.copy(pqcSignerFingerprint = cleaned)
                1 -> d.defaults.copy(classicalSignerFingerprint = cleaned)
                else -> d.defaults.copy(signOnlySignerFingerprint = cleaned)
            }
            data = d.copy(defaults = updated)
            scope.launch { state.edits.setSigningDefaults(updated) }
        }
        DefaultSignerPicker(tr("key_detail_signing_default_pqc"), d.defaults.pqcSignerFingerprint, pool) { save(0, it) }
        DefaultSignerPicker(tr("key_detail_signing_default_classical"), d.defaults.classicalSignerFingerprint, pool) { save(1, it) }
        DefaultSignerPicker(tr("key_detail_signing_default_sign_only"), d.defaults.signOnlySignerFingerprint, pool) { save(2, it) }
    }

    // ── Dialogs ────────────────────────────────────────────────────────
    when (val dlg = dialog) {
        null -> Unit
        ManageDialog.ChangePassphrase -> ChangePassphraseDialog(
            isProtected = d.passphraseProtected,
            onDismiss = { dialog = null }
        ) { old, new, onError ->
            val done = when {
                new.isEmpty() -> tr("change_passphrase_removed")
                d.passphraseProtected -> tr("change_passphrase_changed")
                else -> tr("change_passphrase_set")
            }
            state.runEdit(done, { onError(editErrorMessage(it, tr("change_passphrase_failed"))) }, ::closeAndReload) {
                state.edits.changePassphrase(key.fingerprint, old, new)
            }
        }
        ManageDialog.AddUserId -> AddUserIdDialog(owner, allowPrimary = !composite, onDismiss = { dialog = null }) { uid, primary, pass, onError ->
            state.runEdit(tr("d_status_userid_added"), { onError(editErrorMessage(it, tr("key_detail_add_userid_failed"))) }, ::closeAndReload) {
                state.edits.addUserId(key.fingerprint, uid, primary, pass)
            }
        }
        is ManageDialog.MakePrimary -> UserIdActionDialog(
            title = tr("key_detail_userid_action_sheet_title_make_primary"),
            body = tr("key_detail_userid_action_sheet_subtitle_make_primary", dlg.uid),
            apply = tr("key_detail_userid_action_apply_make_primary"),
            destructive = false,
            onDismiss = { dialog = null }
        ) { pass, onError ->
            state.runEdit(tr("d_status_primary_userid"), { onError(editErrorMessage(it, tr("key_detail_userid_action_failed"))) }, ::closeAndReload) {
                state.edits.setPrimaryUserId(key.fingerprint, dlg.uid, pass)
            }
        }
        is ManageDialog.RevokeUserId -> UserIdActionDialog(
            title = tr("key_detail_userid_action_sheet_title_revoke"),
            body = tr("key_detail_userid_action_sheet_subtitle_revoke", dlg.uid),
            apply = tr("key_detail_userid_action_apply_revoke"),
            destructive = true,
            onDismiss = { dialog = null }
        ) { pass, onError ->
            // Android revokes a User ID with "User ID no longer valid" and asks no reason.
            state.runEdit(tr("d_status_userid_revoked"), { onError(editErrorMessage(it, tr("key_detail_userid_action_failed"))) }, ::closeAndReload) {
                state.edits.revokeUserId(key.fingerprint, dlg.uid, RevocationReason.USER_ID_INVALID, null, pass)
            }
        }
        is ManageDialog.RemoveUserId -> DestructiveConfirmDialog(
            title = tr("key_detail_userid_action_sheet_title_remove"),
            body = tr("key_detail_userid_action_sheet_subtitle_remove", dlg.uid),
            confirmLabel = tr("key_detail_userid_action_apply_remove"),
            onDismiss = { dialog = null },
            onConfirm = {
                dialog = null
                state.runEdit(tr("d_status_userid_removed"), statusError("key_detail_userid_action_failed"), { reload++ }) {
                    state.edits.removeUserId(key.fingerprint, dlg.uid)
                }
            }
        )
        ManageDialog.AddSubkey -> AddSubkeyDialog(
            owner = owner,
            isV6 = key.isV6Key,
            isCompositeSign = composite,
            onDismiss = { dialog = null }
        ) { choice, expirationSeconds, pass, onError ->
            state.runEdit(tr("d_status_subkey_added"), { onError(editErrorMessage(it, tr("key_detail_add_subkey_failed"))) }, ::closeAndReload) {
                state.edits.addSubkey(key.fingerprint, choice, expirationSeconds, pass)
            }
        }
        is ManageDialog.RevokeSubkey -> SubkeyRevokeDialog(dlg.row, onDismiss = { dialog = null }) { args, onError ->
            state.runEdit(
                tr("d_status_subkey_revoked"),
                { t ->
                    if (t is LastEncryptionSubkeyException) dialog = ManageDialog.LastEncryption(dlg.row, args)
                    else onError(editErrorMessage(t, tr("key_detail_subkey_action_failed")))
                },
                ::closeAndReload
            ) {
                state.edits.revokeSubkey(key.fingerprint, dlg.row.fingerprint, args.reason, args.comment, args.passphrase)
            }
        }
        is ManageDialog.RemoveSubkey -> DestructiveConfirmDialog(
            title = tr("key_detail_subkey_remove_confirm_title"),
            body = tr("key_detail_subkey_remove_confirm_body"),
            confirmLabel = tr("key_detail_subkey_remove_confirm_action"),
            onDismiss = { dialog = null },
            onConfirm = {
                dialog = null
                state.runEdit(
                    tr("kd_vm_status_subkey_removed"),
                    { t ->
                        if (t is LastEncryptionSubkeyException) dialog = ManageDialog.LastEncryption(dlg.row, null)
                        else state.status = editErrorMessage(t, tr("key_detail_subkey_action_failed"))
                    },
                    { reload++ }
                ) {
                    state.edits.removeSubkey(key.fingerprint, dlg.row.fingerprint)
                }
            },
            extra = {
                Spacer(Modifier.height(Spacing.Small))
                TextButton(onClick = { dialog = ManageDialog.RevokeSubkey(dlg.row) }) {
                    Text(tr("key_detail_subkey_revoke_instead_button"))
                }
            }
        )
        is ManageDialog.LastEncryption -> BrandDialog(
            onDismissRequest = { dialog = null },
            title = tr("key_detail_subkey_last_enc_title"),
            destructive = true,
            content = { Text(tr("key_detail_subkey_last_enc_body")) },
            confirmButton = {
                TextButton(onClick = {
                    dialog = null
                    val revoke = dlg.revoke
                    if (revoke != null) {
                        state.runEdit(tr("d_status_subkey_revoked"), statusError("key_detail_subkey_action_failed"), { reload++ }) {
                            state.edits.revokeSubkey(
                                key.fingerprint, dlg.row.fingerprint, revoke.reason, revoke.comment, revoke.passphrase,
                                allowLastEncryptionSubkey = true
                            )
                        }
                    } else {
                        state.runEdit(tr("kd_vm_status_subkey_removed"), statusError("key_detail_subkey_action_failed"), { reload++ }) {
                            state.edits.removeSubkey(key.fingerprint, dlg.row.fingerprint, allowLastEncryptionSubkey = true)
                        }
                    }
                }) { Text(tr("key_detail_subkey_last_enc_action"), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { dialog = null }) { Text(tr("common_button_cancel")) } }
        )
        ManageDialog.Notations -> NotationsDialog(owner, d.notations, onDismiss = { dialog = null }) { list, pass, onError ->
            state.runEdit(tr("d_status_notations_saved"), { onError(editErrorMessage(it, tr("key_detail_notations_failed"))) }, ::closeAndReload) {
                state.edits.setNotations(key.fingerprint, list, pass)
            }
        }
    }
}

// ── Building blocks ────────────────────────────────────────────────────

private val MANAGE_DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd")
private fun manageDate(epochMs: Long): String =
    MANAGE_DATE.format(Instant.ofEpochMilli(epochMs).atZone(ZoneId.systemDefault()))

@Composable
private fun ManageLabel(text: String) = Text(text, style = MaterialTheme.typography.titleSmall)

@Composable
private fun ManagePill(text: String, error: Boolean = false) {
    Surface(
        shape = MaterialTheme.shapes.small,
        color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.surfaceVariant
    ) {
        Text(
            text,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
            style = MaterialTheme.typography.labelSmall,
            color = if (error) MaterialTheme.colorScheme.onError else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun KeyRowCard(
    title: String,
    algorithm: String,
    keyId: String,
    capabilities: String,
    createdAt: Long,
    expiresAt: Long?,
    revoked: Boolean,
    actions: @Composable () -> Unit = {}
) {
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Column(Modifier.padding(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, style = MaterialTheme.typography.labelLarge)
                Spacer(Modifier.width(8.dp))
                ManagePill(algorithm)
                if (revoked) { Spacer(Modifier.width(6.dp)); ManagePill(tr("key_detail_revoked_badge"), error = true) }
            }
            Text(
                keyId.uppercase().chunked(4).joinToString(" "),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                if (expiresAt == null) tr("d_keydetail_subkey_meta", capabilities, manageDate(createdAt))
                else tr("d_keydetail_subkey_meta_expires", capabilities, manageDate(createdAt), manageDate(expiresAt)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            actions()
        }
    }
}

@Composable
private fun DefaultSignerPicker(label: String, current: String?, pool: List<PGPKeyEntity>, onPick: (String?) -> Unit) {
    var open by remember { mutableStateOf(false) }
    val self = tr("key_detail_signing_default_self")
    val currentLabel = current?.let { fp -> pool.firstOrNull { it.fingerprint == fp }?.let { it.userID.ifBlank { it.shortFingerprint } } } ?: self
    Column(Modifier.padding(top = 6.dp)) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Box {
            OutlinedButton(onClick = { open = true }, enabled = pool.isNotEmpty()) { Text(currentLabel) }
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                DropdownMenuItem(text = { Text(self) }, onClick = { open = false; onPick(null) })
                pool.forEach { k ->
                    DropdownMenuItem(
                        text = { Text(k.userID.ifBlank { k.shortFingerprint }) },
                        onClick = { open = false; onPick(k.fingerprint) }
                    )
                }
            }
        }
    }
}

@Composable
private fun PassField(value: String, label: String, enabled: Boolean, onChange: (String) -> Unit, isError: Boolean = false) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        isError = isError,
        enabled = enabled,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth()
    )
}

@Composable
private fun ErrorLine(text: String?) {
    if (text != null) {
        Spacer(Modifier.height(Spacing.Small))
        Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    }
}

// ── Dialogs ────────────────────────────────────────────────────────────

/** Android ChangePassphraseSheet: blank new passphrase removes protection, behind an ack. */
@Composable
private fun ChangePassphraseDialog(
    isProtected: Boolean,
    onDismiss: () -> Unit,
    onApply: (old: String, new: String, onError: (String) -> Unit) -> Unit
) {
    var current by remember { mutableStateOf("") }
    var newPass by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var ackRemove by remember { mutableStateOf(false) }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val removing = newPass.isEmpty()
    val matches = newPass == confirm
    val canApply = !working && matches && (!isProtected || current.isNotEmpty()) &&
        (!removing || ackRemove) && !(!isProtected && removing)

    BrandDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = tr("change_passphrase_sheet_title"),
        content = {
            Column(Modifier.heightIn(max = 480.dp).verticalScroll(rememberScrollState())) {
                Text(tr("change_passphrase_sheet_subtitle"), style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(Spacing.Small))
                if (isProtected) PassField(current, tr("change_passphrase_current_label"), !working, { current = it })
                PassField(newPass, tr("change_passphrase_new_label"), !working, { newPass = it })
                PassField(confirm, tr("keyring_generate_passphrase_confirm_label"), !working, { confirm = it }, isError = !matches)
                if (!matches) {
                    Text(tr("keyring_error_passphrase_mismatch"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                if (removing && isProtected) {
                    Spacer(Modifier.height(Spacing.Small))
                    Text(tr("change_passphrase_remove_warning"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = ackRemove, onCheckedChange = { ackRemove = it }, enabled = !working)
                        Text(tr("change_passphrase_remove_ack"), style = MaterialTheme.typography.bodyMedium)
                    }
                }
                Spacer(Modifier.height(Spacing.Small))
                Text(tr("change_passphrase_backup_note"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                ErrorLine(error)
            }
        },
        confirmButton = {
            TextButton(enabled = canApply, onClick = {
                working = true
                error = null
                onApply(current, newPass) { working = false; error = it }
            }) { Text(if (working) tr("d_common_working") else tr("change_passphrase_apply")) }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !working) { Text(tr("common_button_cancel")) } }
    )
}

@Composable
private fun AddUserIdDialog(
    owner: String,
    allowPrimary: Boolean,
    onDismiss: () -> Unit,
    onApply: (uid: String, makePrimary: Boolean, passphrase: String?, onError: (String) -> Unit) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var primary by remember { mutableStateOf(false) }
    var pass by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val emailOk = email.isBlank() || email.contains("@")
    val canApply = !working && name.isNotBlank() && emailOk

    BrandDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = tr("key_detail_add_userid_sheet_title"),
        content = {
            Column {
                Text(tr("key_detail_add_userid_sheet_subtitle", owner), style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(Spacing.Small))
                OutlinedTextField(
                    value = name, onValueChange = { name = it }, singleLine = true, enabled = !working,
                    label = { Text(tr("key_detail_add_userid_name_label")) }, modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = email, onValueChange = { email = it }, singleLine = true, enabled = !working,
                    isError = !emailOk,
                    label = { Text(tr("key_detail_add_userid_email_label")) }, modifier = Modifier.fillMaxWidth()
                )
                if (!emailOk) {
                    Text(tr("keyring_error_email_invalid"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                if (allowPrimary) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = primary, onCheckedChange = { primary = it }, enabled = !working)
                        Text(tr("key_detail_add_userid_make_primary_label"), style = MaterialTheme.typography.bodyMedium)
                    }
                }
                PassField(pass, tr("key_detail_add_userid_passphrase_label"), !working, { pass = it })
                ErrorLine(error)
            }
        },
        confirmButton = {
            TextButton(enabled = canApply, onClick = {
                val uid = if (email.isBlank()) name.trim() else "${name.trim()} <${email.trim()}>"
                working = true
                error = null
                onApply(uid, primary && allowPrimary, pass.ifEmpty { null }) { working = false; error = it }
            }) { Text(if (working) tr("d_common_working") else tr("key_detail_add_userid_apply")) }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !working) { Text(tr("common_button_cancel")) } }
    )
}

/** Make primary or revoke: a sentence and the passphrase. */
@Composable
private fun UserIdActionDialog(
    title: String,
    body: String,
    apply: String,
    destructive: Boolean,
    onDismiss: () -> Unit,
    onApply: (passphrase: String?, onError: (String) -> Unit) -> Unit
) {
    var pass by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    BrandDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = title,
        destructive = destructive,
        content = {
            Column {
                Text(body, style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(Spacing.Small))
                PassField(pass, tr("key_detail_userid_action_passphrase_label"), !working, { pass = it })
                ErrorLine(error)
            }
        },
        confirmButton = {
            TextButton(enabled = !working, onClick = {
                working = true
                error = null
                onApply(pass.ifEmpty { null }) { working = false; error = it }
            }) { Text(if (working) tr("d_common_working") else apply) }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !working) { Text(tr("common_button_cancel")) } }
    )
}

private enum class SubkeyExpiry(val seconds: Long?) {
    NEVER(null),
    ONE_YEAR(365L * 24 * 60 * 60),
    TWO_YEARS(2 * 365L * 24 * 60 * 60),
    FIVE_YEARS(5 * 365L * 24 * 60 * 60)
}

private fun subkeyExpiryLabel(option: SubkeyExpiry): String = when (option) {
    SubkeyExpiry.NEVER -> tr("expiration_never")
    SubkeyExpiry.ONE_YEAR -> tr("expiration_one_year")
    SubkeyExpiry.TWO_YEARS -> tr("expiration_two_years")
    SubkeyExpiry.FIVE_YEARS -> tr("expiration_five_years")
}

internal fun subkeyChoiceLabel(choice: AddSubkeyChoice): String = when (choice) {
    is AddSubkeyChoice.Classical -> when (choice.type) {
        ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_SIGN -> tr("key_detail_add_subkey_type_rsa_2048_sign")
        ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_ENCRYPT -> tr("key_detail_add_subkey_type_rsa_2048_encrypt")
        ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_SIGN -> tr("key_detail_add_subkey_type_rsa_4096_sign")
        ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_ENCRYPT -> tr("key_detail_add_subkey_type_rsa_4096_encrypt")
        ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_AUTH -> tr("key_detail_add_subkey_type_rsa_2048_auth")
        ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_AUTH -> tr("key_detail_add_subkey_type_rsa_4096_auth")
        ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN -> tr("key_detail_add_subkey_type_ed25519_sign")
        ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH -> tr("key_detail_add_subkey_type_ed25519_auth")
        ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT -> tr("key_detail_add_subkey_type_x25519_encrypt")
    }
    is AddSubkeyChoice.PqEncryption -> when (choice.suite) {
        CompositeSuite.IETF_1024 -> tr("key_detail_add_subkey_type_mlkem1024")
        else -> tr("key_detail_add_subkey_type_mlkem768")
    }
    is AddSubkeyChoice.PqSigning -> when (choice.suite) {
        CompositeSignSuite.MLDSA87_ED448 -> tr("key_detail_add_subkey_type_mldsa87")
        else -> tr("key_detail_add_subkey_type_mldsa65")
    }
}

/** Android AddSubkeySheet: the kind (classical or post-quantum), an expiry, the passphrase. */
@Composable
private fun AddSubkeyDialog(
    owner: String,
    isV6: Boolean,
    isCompositeSign: Boolean,
    onDismiss: () -> Unit,
    onApply: (choice: AddSubkeyChoice, expirationSeconds: Long?, passphrase: String?, onError: (String) -> Unit) -> Unit
) {
    val classical = remember(isV6, isCompositeSign) { AddSubkeyChoice.classicalFor(isV6, isCompositeSign) }
    val postQuantum = remember(isV6) { AddSubkeyChoice.postQuantumFor(isV6) }
    var choice by remember { mutableStateOf<AddSubkeyChoice>(classical.first()) }
    var preset by remember { mutableStateOf<SubkeyExpiry?>(SubkeyExpiry.NEVER) }
    var customDate by remember { mutableStateOf(MANAGE_DATE.format(LocalDate.now().plusYears(2))) }
    var pass by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val parsedCustom = runCatching { LocalDate.parse(customDate, MANAGE_DATE) }.getOrNull()
    val customOk = parsedCustom != null && parsedCustom.isAfter(LocalDate.now())
    val canApply = !working && (preset != null || customOk)

    @Composable
    fun ChoiceRow(c: AddSubkeyChoice) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = choice == c, onClick = { choice = c }, enabled = !working)
            Text(subkeyChoiceLabel(c), style = MaterialTheme.typography.bodyMedium)
        }
    }

    BrandDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = tr("key_detail_add_subkey_sheet_title"),
        content = {
            Column(Modifier.heightIn(max = 520.dp).verticalScroll(rememberScrollState())) {
                Text(tr("key_detail_add_subkey_sheet_subtitle", owner), style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(Spacing.Small))
                Text(tr("key_detail_add_subkey_type_label"), style = MaterialTheme.typography.labelLarge)
                Text(tr("key_detail_add_subkey_group_classical"), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                classical.forEach { ChoiceRow(it) }
                if (isCompositeSign) {
                    Text(tr("key_detail_add_subkey_v6_note"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
                }
                Text(tr("key_detail_add_subkey_group_pq"), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                postQuantum.forEach { ChoiceRow(it) }

                Spacer(Modifier.height(Spacing.Small))
                Text(tr("key_detail_add_subkey_expiry_label"), style = MaterialTheme.typography.labelLarge)
                SubkeyExpiry.entries.forEach { opt ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = preset == opt, onClick = { preset = opt }, enabled = !working)
                        Text(subkeyExpiryLabel(opt), style = MaterialTheme.typography.bodyMedium)
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = preset == null, onClick = { preset = null }, enabled = !working)
                    Text(tr("key_detail_expiry_custom"), style = MaterialTheme.typography.bodyMedium)
                }
                if (preset == null) {
                    OutlinedTextField(
                        value = customDate, onValueChange = { customDate = it }, singleLine = true, enabled = !working,
                        isError = !customOk,
                        label = { Text(tr("d_keydetail_expiry_date_label")) }, modifier = Modifier.fillMaxWidth()
                    )
                }
                Spacer(Modifier.height(Spacing.Small))
                PassField(pass, tr("key_detail_add_subkey_passphrase_label"), !working, { pass = it })
                ErrorLine(error)
            }
        },
        confirmButton = {
            TextButton(enabled = canApply, onClick = {
                val p = preset
                val expiresAt = if (p != null) p.seconds?.let { System.currentTimeMillis() / 1000L + it }
                else parsedCustom!!.atStartOfDay(ZoneId.systemDefault()).toEpochSecond()
                // The generators take a lifetime from the subkey's creation, which is now.
                val lifetime = expiresAt?.let { (it - System.currentTimeMillis() / 1000L).coerceAtLeast(1L) }
                working = true
                error = null
                onApply(choice, lifetime, pass.ifEmpty { null }) { working = false; error = it }
            }) { Text(if (working) tr("d_common_working") else tr("key_detail_add_subkey_apply")) }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !working) { Text(tr("common_button_cancel")) } }
    )
}

private val SUBKEY_REASONS = listOf(
    RevocationReason.NO_REASON,
    RevocationReason.SUPERSEDED,
    RevocationReason.COMPROMISED,
    RevocationReason.RETIRED
)

@Composable
private fun SubkeyRevokeDialog(
    row: DesktopKeyEdits.SubkeyRow,
    onDismiss: () -> Unit,
    onApply: (RevokeArgs, onError: (String) -> Unit) -> Unit
) {
    var reason by remember { mutableStateOf(RevocationReason.SUPERSEDED) }
    var comment by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    BrandDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = tr("d_keydetail_subkey_revoke_title", row.keyId.uppercase().chunked(4).joinToString(" ")),
        destructive = true,
        content = {
            Column(Modifier.heightIn(max = 480.dp).verticalScroll(rememberScrollState())) {
                Text(tr("d_keydetail_subkey_revoke_body"), style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(Spacing.Small))
                SUBKEY_REASONS.forEach { r ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = reason == r, onClick = { reason = r }, enabled = !working)
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
                OutlinedTextField(
                    value = comment, onValueChange = { comment = it }, singleLine = true, enabled = !working,
                    label = { Text(tr("revoke_sheet_comment_label")) }, modifier = Modifier.fillMaxWidth()
                )
                PassField(pass, tr("key_detail_expiry_passphrase_label"), !working, { pass = it })
                ErrorLine(error)
            }
        },
        confirmButton = {
            TextButton(enabled = !working, onClick = {
                working = true
                error = null
                onApply(RevokeArgs(reason, comment.ifBlank { null }, pass.ifEmpty { null })) { working = false; error = it }
            }) {
                Text(if (working) tr("d_common_working") else tr("revoke_sheet_confirm"), color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !working) { Text(tr("common_button_cancel")) } }
    )
}

/** Android EditNotationsSheet: name and value rows; each name needs an @ and a value. */
@Composable
private fun NotationsDialog(
    owner: String,
    initial: List<UserIdService.Notation>,
    onDismiss: () -> Unit,
    onApply: (List<UserIdService.Notation>, passphrase: String?, onError: (String) -> Unit) -> Unit
) {
    val rows = remember { mutableStateListOf<Pair<String, String>>().apply { addAll(initial.map { it.name to it.value }) } }
    var pass by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val valid = rows.all { (n, v) -> n.contains("@") && v.isNotBlank() }

    BrandDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = tr("key_detail_notations_sheet_title"),
        content = {
            Column(Modifier.heightIn(max = 520.dp).verticalScroll(rememberScrollState())) {
                Text(tr("key_detail_notations_sheet_subtitle", owner), style = MaterialTheme.typography.bodyMedium)
                if (rows.isEmpty()) {
                    Spacer(Modifier.height(Spacing.Small))
                    Text(tr("key_detail_notations_sheet_empty"), style = MaterialTheme.typography.bodySmall)
                }
                rows.forEachIndexed { i, (n, v) ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = n, onValueChange = { rows[i] = it to rows[i].second }, singleLine = true,
                            enabled = !working, isError = !n.contains("@"),
                            label = { Text(tr("key_detail_notations_name_label")) }, modifier = Modifier.weight(1f)
                        )
                        Spacer(Modifier.width(6.dp))
                        OutlinedTextField(
                            value = v, onValueChange = { rows[i] = rows[i].first to it }, singleLine = true,
                            enabled = !working, isError = v.isBlank(),
                            label = { Text(tr("key_detail_notations_value_label")) }, modifier = Modifier.weight(1f)
                        )
                        IconButton(onClick = { rows.removeAt(i) }, enabled = !working) {
                            Icon(Icons.Filled.Close, contentDescription = tr("key_detail_notations_remove_row"))
                        }
                    }
                }
                TextButton(onClick = { rows.add("" to "") }, enabled = !working) { Text(tr("key_detail_notations_add_row")) }
                Text(tr("key_detail_notations_name_hint"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(Spacing.Small))
                PassField(pass, tr("key_detail_userid_action_passphrase_label"), !working, { pass = it })
                ErrorLine(error)
            }
        },
        confirmButton = {
            TextButton(enabled = !working && valid, onClick = {
                working = true
                error = null
                onApply(rows.map { (n, v) -> UserIdService.Notation(n.trim(), v.trim()) }, pass.ifEmpty { null }) {
                    working = false; error = it
                }
            }) { Text(if (working) tr("d_common_working") else tr("key_detail_notations_apply")) }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !working) { Text(tr("common_button_cancel")) } }
    )
}
