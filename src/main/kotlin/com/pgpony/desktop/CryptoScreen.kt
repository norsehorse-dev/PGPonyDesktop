// CryptoScreen.kt
// PGPony Desktop — D3a: the four text-mode crypto surfaces (Encrypt · Decrypt · Sign · Verify)
// on the vendored engine. Encrypt offers public-key (multi-recipient, optional sign-as — checked
// by default when a signer exists, the Android sign-by-default posture) or passphrase (symmetric)
// modes; the SEIPDv2/AEAD all-v6 gating lives inside the vendored encrypt and needs no porting.
// Revoked keys are excluded from recipients and signers (the Android availableRecipients rule).
// File operations, MIME, and Bundle compose are D3b/D3c.
//
// D11b — LOCALIZATION. Every user-visible string on this screen is a key now. Where Android
// already says the same sentence the ANDROID key is reused (encrypt_recipients_label,
// encrypt_sign_as_label, encrypt_password_confirm_label, common_processing …) and five
// translations come for free; a `d_crypto_*` key is minted only where the desktop genuinely
// says something the phone doesn't — the Files tab, the drop hint, the detached-verify pairing
// rule, the on-card batch titles.
//
// The banner sentences are assembled from a stem plus optional suffix fragments
// (`d_crypto_banner_signer_suffix`, `…_keyid_suffix`, `…_attach_suffix`) because the same three
// optional clauses attach to six different stems. Each fragment carries its own leading
// separator so a translator can move the punctuation; they are commented as fragments in
// i18n/values/strings.xml so nobody tries to read them as standalone sentences.

package com.pgpony.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Description
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.crypto.SignedInputType
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.crypto.mime.MimeAttachment
import com.pgpony.android.data.PGPKeyEntity
import androidx.compose.ui.awt.AwtWindow
import kotlinx.coroutines.launch
import java.awt.FileDialog
import java.awt.Frame
import java.nio.file.Path

// The label is a KEY, not a resolved string. An enum constant is initialized once per process,
// so a resolved label would freeze whatever language happened to be current at class-load time
// and never move again when the picker changes; resolution has to happen at the draw site,
// inside composition, where the snapshot read subscribes the row to I18n.language.
//
// Four of the five tab labels are Android keys — the phone app already says Encrypt, Decrypt,
// Sign and Verify in six languages. Only "Files" is desktop-owned, because Android's file mode
// is a sub-mode of Encrypt rather than a tab of its own.
private enum class CryptoTab(val labelKey: String) {
    ENCRYPT("main_tab_encrypt"),
    DECRYPT("main_tab_decrypt"),
    SIGN("encrypt_action_sign"),
    VERIFY("verify_file_verify_button"),
    FILES("d_crypto_tab_files")
}

private enum class FileOp(val labelKey: String) {
    ENCRYPT("encrypt_action_encrypt"),
    DECRYPT("decrypt_action_decrypt"),
    SIGN("d_crypto_fileop_sign"),
    VERIFY("d_crypto_fileop_verify")
}

private enum class EncryptWith { PUBLIC_KEYS, PASSPHRASE }

/** Outcome banner state for the output pane. */
private sealed class Banner(val text: String, val tone: Tone) {
    enum class Tone { GOOD, BAD, WARN, NEUTRAL }
    class Good(text: String) : Banner(text, Tone.GOOD)
    class Bad(text: String) : Banner(text, Tone.BAD)
    class Warn(text: String) : Banner(text, Tone.WARN)
    class Info(text: String) : Banner(text, Tone.NEUTRAL)
}

@Composable
fun CryptoScreen(state: DesktopState) {
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val crypto = state.repository

    var tab by remember { mutableStateOf(CryptoTab.ENCRYPT) }
    // Per-tab input (field report: text typed in Encrypt used to follow you to Decrypt).
    val inputs = remember { mutableStateMapOf<CryptoTab, String>() }
    val input = inputs[tab] ?: ""
    var output by remember { mutableStateOf("") }
    var banner by remember { mutableStateOf<Banner?>(null) }
    var busy by remember { mutableStateOf(false) }

    // Encrypt options
    var encryptWith by remember { mutableStateOf(EncryptWith.PUBLIC_KEYS) }
    var selectedRecipients by remember { mutableStateOf(setOf<String>()) }
    var signEnabled by remember { mutableStateOf(true) }
    var signerFp by remember { mutableStateOf<String?>(null) }
    var signerPass by remember { mutableStateOf("") }
    var symPass by remember { mutableStateOf("") }
    var symPassConfirm by remember { mutableStateOf("") }

    // Decrypt options
    var decryptPass by remember { mutableStateOf("") }

    // Sign options
    var detachedMode by remember { mutableStateOf(false) }

    // Verify options
    var detachedContent by remember { mutableStateOf("") }

    // Bundles + structured decrypt (D3c)
    var attachments by remember { mutableStateOf<List<Path>>(emptyList()) }
    var showAttachPicker by remember { mutableStateOf(false) }
    var showSaveEml by remember { mutableStateOf(false) }
    var decryptedAttachments by remember { mutableStateOf<List<MimeAttachment>>(emptyList()) }
    var savingAttachment by remember { mutableStateOf<MimeAttachment?>(null) }
    val mimeOps = remember { MimeOps(state.repository) }

    // Files tab (D3b)
    var showMultiFilePicker by remember { mutableStateOf(false) }
    var fileList by remember { mutableStateOf<List<Path>>(emptyList()) }
    var fileOp by remember { mutableStateOf(FileOp.ENCRYPT) }
    var fileOpTouched by remember { mutableStateOf(false) }
    var fileArmor by remember { mutableStateOf(false) }
    var fileResults by remember { mutableStateOf<List<FileCryptoOps.FileOutcome>>(emptyList()) }
    val fileOps = remember { FileCryptoOps(state.repository) }

    // D9 — a classified file/text open routes here (import & restore are handled elsewhere).
    androidx.compose.runtime.LaunchedEffect(state.pendingOpen) {
        when (val a = state.pendingOpen) {
            is OpenAction.DecryptText -> { tab = CryptoTab.DECRYPT; inputs[CryptoTab.DECRYPT] = a.armored; banner = null; state.consumePendingOpen() }
            is OpenAction.EncryptText -> { tab = CryptoTab.ENCRYPT; inputs[CryptoTab.ENCRYPT] = a.text; banner = null; state.consumePendingOpen() }
            is OpenAction.DecryptFile -> { tab = CryptoTab.FILES; if (a.path !in fileList) fileList = fileList + a.path; fileOp = FileOp.DECRYPT; fileOpTouched = true; state.consumePendingOpen() }
            is OpenAction.EncryptFile -> { tab = CryptoTab.FILES; if (a.path !in fileList) fileList = fileList + a.path; fileOp = FileOp.ENCRYPT; fileOpTouched = true; state.consumePendingOpen() }
            is OpenAction.VerifyDetachedSignature -> { tab = CryptoTab.FILES; if (a.path !in fileList) fileList = fileList + a.path; fileOp = FileOp.VERIFY; fileOpTouched = true; state.consumePendingOpen() }
            else -> Unit
        }
    }

    // Window drops land here: append, auto-route the operation, switch to the Files tab.
    androidx.compose.runtime.LaunchedEffect(state.droppedFiles) {
        if (state.droppedFiles.isNotEmpty()) {
            val incoming = state.droppedFiles.filter { it !in fileList }
            fileList = fileList + incoming
            if (!fileOpTouched && incoming.isNotEmpty()) {
                fileOp = if (incoming.all { FileCryptoOps.looksEncrypted(it) }) FileOp.DECRYPT
                else FileOp.ENCRYPT
            }
            tab = CryptoTab.FILES
            state.consumeDroppedFiles()
        }
    }

    // Recipients: the Android availableRecipients rule — a card-backed row is only a usable
    // recipient once its PUBLIC certificate is present (pairing alone stores no key material,
    // so a card row with null armor can't be encrypted to).
    val recipients = state.keys.filter {
        !it.isRevoked && !it.isExpired && (!it.isCardBacked || it.armoredPublicKey != null)
    }
    // Signers: software key pairs OR paired card-backed keys (the Android availableSigners set).
    val signers = state.keys.filter {
        !it.isRevoked && (it.isKeyPair || (it.isCardBacked && it.armoredPublicKey != null))
    }
    val effectiveSigner = signerFp?.let { fp -> signers.firstOrNull { it.fingerprint == fp } }
        ?: signers.firstOrNull { it.isDefault } ?: signers.firstOrNull()

    // D7 — a pending hardware-key operation; when set, the PIN-and-run dialog is shown.
    var pendingCardOp by remember { mutableStateOf<CardOpRequest?>(null) }

    fun run(block: suspend () -> Unit) {
        scope.launch {
            busy = true
            banner = null
            try {
                block()
            } catch (t: Throwable) {
                banner = Banner.Bad(t.message ?: t::class.simpleName ?: tr("d_crypto_err_generic"))
            } finally {
                busy = false
            }
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(Spacing.Section)) {
        // D12 — the tab strip is this screen's masthead, so it takes the gradient rule the other
        // four screens get from ScreenHeader. The TabRow container goes transparent because its
        // default `surface` fill drew a second, slightly different background inside the window.
        TabRow(selectedTabIndex = tab.ordinal, containerColor = Color.Transparent) {
            CryptoTab.entries.forEach { t ->
                Tab(
                    selected = tab == t,
                    onClick = { tab = t; banner = null; output = ""; decryptedAttachments = emptyList() },
                    text = { Text(tr(t.labelKey)) }
                )
            }
        }
        BrandRule()
        Spacer(Modifier.height(Spacing.Large))

        // ── Files surface (D3b) ─────────────────────────────────────────
        if (tab == CryptoTab.FILES) {
            Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                // WrapRow, not Row: four radio-plus-label pairs in German ("Entschlüsseln",
                // "Signieren", "Überprüfen") overflow a narrow window, and a bare Row would
                // compress the last label rather than move it.
                WrapRow(horizontalSpacing = Spacing.Medium) {
                    FileOp.entries.forEach { op ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = fileOp == op,
                                onClick = { fileOp = op; fileOpTouched = true },
                                enabled = !busy
                            )
                            Text(tr(op.labelKey), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
                Spacer(Modifier.height(Spacing.Medium))
                WrapRow {
                    OutlinedButton(
                        onClick = { showMultiFilePicker = true },
                        enabled = !busy,
                        shape = RoundedCornerShape(Radius.Small)
                    ) {
                        Text(tr("d_crypto_add_files"))
                    }
                    TextButton(
                        onClick = { fileList = emptyList(); fileResults = emptyList(); banner = null },
                        enabled = fileList.isNotEmpty() || fileResults.isNotEmpty()
                    ) { Text(tr("common_button_clear")) }
                    Text(
                        tr("d_crypto_drop_hint"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Spacer(Modifier.height(Spacing.Medium))
                if (fileList.isEmpty()) {
                    // No fillMaxSize — this column scrolls, and a fill modifier under an
                    // unbounded height constraint resolves to zero.
                    EmptyState(
                        icon = Icons.Filled.Description,
                        title = tr("d_crypto_no_files_title"),
                        message = tr("d_crypto_no_files")
                    ) {
                        OutlinedButton(onClick = { showMultiFilePicker = true }, enabled = !busy) {
                            Text(tr("d_crypto_add_files"))
                        }
                    }
                }
                fileList.forEach { p -> FileRow(p, enabled = !busy) { fileList = fileList - p } }

                Spacer(Modifier.height(Spacing.Large))
                when (fileOp) {
                    FileOp.ENCRYPT -> {
                        SubHeading(tr("encrypt_recipients_label"))
                        recipients.forEach { key ->
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(
                                    checked = key.fingerprint in selectedRecipients,
                                    onCheckedChange = { checked ->
                                        selectedRecipients =
                                            if (checked) selectedRecipients + key.fingerprint
                                            else selectedRecipients - key.fingerprint
                                    }
                                )
                                Text(
                                    "${key.userID.ifBlank { key.shortFingerprint }} · ${key.algorithm.displayName}",
                                    style = MaterialTheme.typography.bodyMedium
                                )
                            }
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = signEnabled && effectiveSigner != null,
                                onCheckedChange = { signEnabled = it },
                                enabled = effectiveSigner != null
                            )
                            Text(tr("encrypt_sign_as_label"))
                            Spacer(Modifier.width(8.dp))
                            SignerPicker(signers, effectiveSigner, enabled = signEnabled) { signerFp = it }
                        }
                        if (signEnabled && effectiveSigner != null) {
                            OutlinedTextField(
                                value = signerPass, onValueChange = { signerPass = it },
                                label = { Text(tr("d_crypto_signer_pass_label")) },
                                singleLine = true,
                                visualTransformation = PasswordVisualTransformation(),
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = fileArmor, onCheckedChange = { fileArmor = it })
                            Text(tr("d_crypto_armor_gpg"))
                        }
                    }
                    FileOp.DECRYPT -> {
                        OutlinedTextField(
                            value = decryptPass, onValueChange = { decryptPass = it },
                            label = { Text(tr("d_crypto_decrypt_pass_label")) }, singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth()
                        )
                        Text(
                            tr("d_crypto_decrypt_files_note"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    FileOp.SIGN -> {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(tr("d_crypto_sign_as_colon"), style = MaterialTheme.typography.titleSmall)
                            Spacer(Modifier.width(8.dp))
                            SignerPicker(signers, effectiveSigner, enabled = true) { signerFp = it }
                        }
                        OutlinedTextField(
                            value = signerPass, onValueChange = { signerPass = it },
                            label = { Text(tr("d_crypto_signer_pass_label")) },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth()
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = fileArmor, onCheckedChange = { fileArmor = it })
                            Text(tr("d_crypto_armor_sig"))
                        }
                    }
                    FileOp.VERIFY -> {
                        Text(
                            tr("d_crypto_verify_files_hint"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                Spacer(Modifier.height(Spacing.Large))
                BrandButton(
                    enabled = !busy && fileList.isNotEmpty() && when (fileOp) {
                        FileOp.ENCRYPT -> selectedRecipients.isNotEmpty()
                        FileOp.SIGN -> effectiveSigner != null
                        else -> true
                    },
                    onClick = {
                        // D7 — does this batch need the card? SIGN/ENCRYPT when the signer is a
                        // card key; DECRYPT when any file is addressed to a paired card key.
                        val signerOnCard = DesktopCardOps.signsOnCard(effectiveSigner)
                        run {
                            val cardBatch: CardOpRequest? = when (fileOp) {
                                FileOp.SIGN -> if (signerOnCard)
                                    buildCardFileSign(state, fileOps, fileList, effectiveSigner!!, fileArmor) {
                                        r -> fileResults = r; banner = fileBanner(r)
                                    } else null
                                FileOp.ENCRYPT -> if (signEnabled && signerOnCard)
                                    buildCardFileEncrypt(
                                        state, fileOps, fileList, selectedRecipients, effectiveSigner!!, fileArmor
                                    ) { r -> fileResults = r; banner = fileBanner(r) } else null
                                FileOp.DECRYPT -> buildCardFileDecrypt(
                                    state, fileOps, fileList, decryptPass.ifBlank { null }
                                ) { r -> fileResults = r; banner = fileBanner(r) }
                                FileOp.VERIFY -> null
                            }
                            if (cardBatch != null) {
                                pendingCardOp = cardBatch
                                return@run
                            }
                            val outcomes = mutableListOf<FileCryptoOps.FileOutcome>()
                            when (fileOp) {
                                FileOp.ENCRYPT -> {
                                    val signFp = if (signEnabled && effectiveSigner != null)
                                        effectiveSigner.fingerprint else null
                                    for (f in fileList) outcomes += fileOps.encryptFile(
                                        f, selectedRecipients, signFp, signerPass.ifBlank { null }, fileArmor
                                    )
                                }
                                FileOp.DECRYPT -> for (f in fileList)
                                    outcomes += fileOps.decryptFile(f, decryptPass.ifBlank { null })
                                FileOp.SIGN -> {
                                    val s = effectiveSigner ?: error(tr("d_crypto_err_no_signer"))
                                    for (f in fileList) outcomes += fileOps.signFileDetached(
                                        f, s.fingerprint, signerPass.ifBlank { null }, fileArmor
                                    )
                                }
                                FileOp.VERIFY -> {
                                    val pairs = FileCryptoOps.pairDetached(fileList)
                                    check(pairs.isNotEmpty()) {
                                        tr("d_crypto_err_no_pairing")
                                    }
                                    for ((sig, content) in pairs)
                                        outcomes += fileOps.verifyFileDetached(sig, content)
                                }
                            }
                            fileResults = outcomes
                            val ok = outcomes.count { it.ok }
                            banner = if (ok == outcomes.size)
                                Banner.Good(tr("d_crypto_files_done", ok, outcomes.size))
                            else Banner.Warn(tr("d_crypto_files_partial", ok, outcomes.size))
                        }
                    }
                ) { Text(if (busy) tr("common_processing") else tr("d_crypto_run_op", tr(fileOp.labelKey))) }

                banner?.let { b ->
                    Spacer(Modifier.height(Spacing.Large))
                    BannerStrip(b)
                }

                Spacer(Modifier.height(Spacing.Medium))
                fileResults.forEach { r ->
                    Card(
                        shape = RoundedCornerShape(Radius.Small),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant
                        ),
                        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)
                    ) {
                        Column(modifier = Modifier.padding(Spacing.Medium)) {
                            // The ✓/✗ glyphs were the only status indicator in the app that
                            // depended on the reader's font having them; a badge says the same
                            // thing in words the audit can check.
                            WrapRow(horizontalSpacing = Spacing.Small, verticalSpacing = Spacing.Tight) {
                                BrandBadge(
                                    if (r.ok) tr("d_crypto_result_ok") else tr("d_crypto_result_failed"),
                                    if (r.ok) BadgeTone.Brand else BadgeTone.Error
                                )
                                Text(
                                    r.input.fileName.toString(),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                            }
                            Spacer(Modifier.height(Spacing.Tight))
                            Text(
                                r.detail,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            r.output?.let {
                                Text(
                                    "→ $it",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }

            if (showMultiFilePicker) {
                MultiFileDialog { picked ->
                    showMultiFilePicker = false
                    val incoming = picked.map { it.toPath() }.filter { it !in fileList }
                    fileList = fileList + incoming
                    if (!fileOpTouched && incoming.isNotEmpty()) {
                        fileOp = if (incoming.all { FileCryptoOps.looksEncrypted(it) }) FileOp.DECRYPT
                        else FileOp.ENCRYPT
                    }
                }
            }
            return@Column
        }

        Row(modifier = Modifier.fillMaxSize()) {

            // ── Left: input + options ───────────────────────────────────
            Column(
                modifier = Modifier.weight(1f).fillMaxSize().verticalScroll(rememberScrollState())
            ) {
                OutlinedTextField(
                    value = input, onValueChange = { inputs[tab] = it },
                    label = {
                        Text(
                            when (tab) {
                                CryptoTab.ENCRYPT -> tr("encrypt_input_label_message_to_encrypt")
                                CryptoTab.DECRYPT -> tr("decrypt_input_paste_label")
                                CryptoTab.SIGN -> tr("encrypt_input_label_message_to_sign")
                                CryptoTab.VERIFY -> tr("d_crypto_input_verify")
                                CryptoTab.FILES -> ""   // unreachable — Files renders its own pane
                            }
                        )
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 200.dp, max = 320.dp)
                )
                Spacer(Modifier.height(10.dp))

                when (tab) {
                    CryptoTab.ENCRYPT -> {
                        // WrapRow: the label plus two radio-and-word pairs is the widest control
                        // group on the left pane, and the pane is already only half the window.
                        WrapRow(horizontalSpacing = Spacing.Medium) {
                            Text(
                                tr("d_crypto_encrypt_with"),
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                RadioButton(
                                    selected = encryptWith == EncryptWith.PUBLIC_KEYS,
                                    onClick = { encryptWith = EncryptWith.PUBLIC_KEYS })
                                Text(tr("d_crypto_with_public_keys"))
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                RadioButton(
                                    selected = encryptWith == EncryptWith.PASSPHRASE,
                                    onClick = { encryptWith = EncryptWith.PASSPHRASE })
                                Text(tr("encrypt_password_passphrase_label"))
                            }
                        }
                        if (encryptWith == EncryptWith.PUBLIC_KEYS) {
                            Spacer(Modifier.height(Spacing.Medium))
                            SubHeading(tr("encrypt_recipients_label"))
                            if (recipients.isEmpty()) {
                                Text(
                                    tr("encrypt_recipients_no_keys"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            recipients.forEach { key ->
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Checkbox(
                                        checked = key.fingerprint in selectedRecipients,
                                        onCheckedChange = { checked ->
                                            selectedRecipients =
                                                if (checked) selectedRecipients + key.fingerprint
                                                else selectedRecipients - key.fingerprint
                                        }
                                    )
                                    Text(
                                        "${key.userID.ifBlank { key.shortFingerprint }} · ${key.algorithm.displayName}",
                                        style = MaterialTheme.typography.bodyMedium
                                    )
                                }
                            }
                            Spacer(Modifier.height(8.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(
                                    checked = signEnabled && effectiveSigner != null,
                                    onCheckedChange = { signEnabled = it },
                                    enabled = effectiveSigner != null
                                )
                                Text(tr("encrypt_sign_as_label"))
                                Spacer(Modifier.width(8.dp))
                                SignerPicker(signers, effectiveSigner, enabled = signEnabled) { signerFp = it }
                            }
                            if (signEnabled && effectiveSigner != null) {
                                OutlinedTextField(
                                    value = signerPass, onValueChange = { signerPass = it },
                                    label = { Text(tr("d_crypto_signer_pass_label")) },
                                    singleLine = true,
                                    visualTransformation = PasswordVisualTransformation(),
                                    modifier = Modifier.fillMaxWidth()
                                )
                            }
                        } else {
                            Spacer(Modifier.height(6.dp))
                            OutlinedTextField(
                                value = symPass, onValueChange = { symPass = it },
                                label = { Text(tr("encrypt_password_passphrase_label")) }, singleLine = true,
                                visualTransformation = PasswordVisualTransformation(),
                                modifier = Modifier.fillMaxWidth()
                            )
                            Spacer(Modifier.height(6.dp))
                            OutlinedTextField(
                                value = symPassConfirm, onValueChange = { symPassConfirm = it },
                                label = { Text(tr("encrypt_password_confirm_label")) }, singleLine = true,
                                visualTransformation = PasswordVisualTransformation(),
                                isError = symPassConfirm.isNotBlank() && symPass != symPassConfirm,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                        // ── Attachments (D3c — PGP/MIME bundle) ─────────
                        Spacer(Modifier.height(8.dp))
                        WrapRow {
                            OutlinedButton(onClick = { showAttachPicker = true }, enabled = !busy) {
                                Text(tr("d_crypto_attach_files"))
                            }
                            if (attachments.isNotEmpty()) {
                                TextButton(onClick = { attachments = emptyList() }) { Text(tr("d_crypto_clear_attachments")) }
                            }
                        }
                        attachments.forEach { p ->
                            WrapRow(horizontalSpacing = Spacing.Small, verticalSpacing = Spacing.Tight) {
                                Text(
                                    p.fileName.toString(),
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                TextButton(onClick = { attachments = attachments - p }) {
                                    Text(tr("d_common_remove"))
                                }
                            }
                        }
                        if (attachments.isNotEmpty()) {
                            Text(
                                tr("d_crypto_bundle_note", attachments.size),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        Spacer(Modifier.height(10.dp))
                        BrandButton(
                            enabled = !busy && (input.isNotBlank() || attachments.isNotEmpty()) && when (encryptWith) {
                                EncryptWith.PUBLIC_KEYS -> selectedRecipients.isNotEmpty()
                                EncryptWith.PASSPHRASE -> symPass.isNotBlank() && symPass == symPassConfirm
                            },
                            onClick = {
                                val signWith0 = if (signEnabled && effectiveSigner != null) effectiveSigner else null
                                // D7 — card-signed encrypt (PUBLIC_KEYS only; the whole encrypt
                                // runs with the card connected because the signer taps it).
                                if (signWith0 != null && DesktopCardOps.signsOnCard(signWith0) &&
                                    encryptWith == EncryptWith.PUBLIC_KEYS
                                ) run {
                                    val cardRing = crypto.loadPublicKeyRing(signWith0.fingerprint)
                                    val cardPubKey = cardRing?.let {
                                        com.pgpony.android.crypto.card.CardSigningService.shared
                                            .signingPublicKey(it, signWith0.cardSigFingerprint)
                                    }
                                    val rings = selectedRecipients.mapNotNull { crypto.loadPublicKeyRing(it) }
                                    if (cardPubKey == null || rings.size != selectedRecipients.size) {
                                        banner = Banner.Bad(tr("d_crypto_err_card_or_recipient_load"))
                                    } else {
                                        pendingCardOp = CardOpRequest(
                                            tr(
                                                "d_crypto_card_sign_encrypt_title",
                                                signWith0.userID.ifBlank { tr("d_crypto_hardware_key") }
                                            )
                                        ) { session, pin ->
                                            output = if (attachments.isEmpty())
                                                crypto.encryptTextWithCardSigner(input, rings, session, pin, cardPubKey)
                                            else
                                                mimeOps.encryptBundleWithCardSigner(
                                                    input, attachments, selectedRecipients, session, pin, cardPubKey
                                                )
                                            val bundleNote = if (attachments.isEmpty()) ""
                                            else tr("d_crypto_banner_bundle_suffix", attachments.size)
                                            banner = Banner.Good(
                                                tr(
                                                    "d_crypto_banner_encrypted_card",
                                                    selectedRecipients.size, signWith0.userEmail
                                                ) + bundleNote
                                            )
                                        }
                                    }
                                } else run {
                                    // Signing must never silently downgrade (the Phase A3 rule):
                                    // if Sign-as is on, a loadable secret ring is REQUIRED —
                                    // any failure aborts the whole encrypt with a named error.
                                    val signWith = signWith0
                                    output = when (encryptWith) {
                                        EncryptWith.PUBLIC_KEYS -> {
                                            if (attachments.isEmpty()) {
                                                val loaded = selectedRecipients.map { fp -> fp to crypto.loadPublicKeyRing(fp) }
                                                loaded.firstOrNull { it.second == null }?.let { (fp, _) ->
                                                    val name = state.keys.firstOrNull { it.fingerprint == fp }
                                                        ?.userID?.ifBlank { null } ?: fp.take(16)
                                                    error(tr("d_crypto_err_pubkey_missing", name))
                                                }
                                                val rings = loaded.mapNotNull { it.second }
                                                val signerRing = signWith?.let {
                                                    crypto.loadSecretKeyRing(it.fingerprint)
                                                        ?: error(
                                                            tr("d_crypto_err_signer_load", it.shortFingerprint)
                                                        )
                                                }
                                                crypto.encryptText(
                                                    input, rings, signerRing, signerPass.ifBlank { null }
                                                )
                                            } else mimeOps.encryptBundle(
                                                input, attachments, selectedRecipients,
                                                signWith?.fingerprint, signerPass.ifBlank { null }
                                            )
                                        }
                                        EncryptWith.PASSPHRASE ->
                                            if (attachments.isEmpty()) crypto.encryptTextSymmetric(input, symPass)
                                            else mimeOps.encryptBundleSymmetric(input, attachments, symPass)
                                    }
                                    val bundleNote = if (attachments.isEmpty()) ""
                                    else tr("d_crypto_banner_bundle_suffix", attachments.size)
                                    banner = Banner.Good(
                                        (if (encryptWith == EncryptWith.PUBLIC_KEYS)
                                            tr("d_crypto_banner_encrypted", selectedRecipients.size) +
                                                (signWith?.let {
                                                    tr("d_crypto_banner_signed_as", it.userEmail, it.shortFingerprint)
                                                } ?: tr("d_crypto_banner_unsigned"))
                                        else tr("d_crypto_banner_encrypted_pass")) + bundleNote
                                    )
                                }
                            }
                        ) { Text(if (busy) tr("common_processing") else tr("encrypt_action_encrypt")) }
                    }

                    CryptoTab.DECRYPT -> {
                        OutlinedTextField(
                            value = decryptPass, onValueChange = { decryptPass = it },
                            label = { Text(tr("d_crypto_decrypt_pass_label")) }, singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(10.dp))
                        Text(
                            tr("d_crypto_decrypt_note"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(6.dp))
                        BrandButton(
                            enabled = !busy && input.contains("-----BEGIN PGP"),
                            onClick = {
                                run {
                                    // D7 — if the message is addressed to a paired card key, decrypt
                                    // on the hardware (PIN-and-tap) instead of in software.
                                    val armoredForCard = MimeOps.pgpPayload(input)
                                    val match = DesktopCardOps.matchCardDecryptKey(
                                        armoredForCard.toByteArray(Charsets.UTF_8), crypto
                                    )
                                    if (match != null) {
                                        busy = true
                                        pendingCardOp = CardOpRequest(
                                            tr(
                                                "d_crypto_card_decrypt_title",
                                                match.entity.userID.ifBlank { tr("d_crypto_hardware_key") }
                                            )
                                        ) { session, pin ->
                                            val r = com.pgpony.android.crypto.card.CardDecryptService.shared
                                                .decryptBytes(
                                                    session, match.ring, pin,
                                                    armoredForCard.toByteArray(Charsets.UTF_8),
                                                    verificationKeys = state.keys.mapNotNull {
                                                        crypto.loadPublicKeyRing(it.fingerprint)
                                                    }
                                                )
                                            val structured = mimeOps.structuredFromBytes(
                                                r.data, r.signatureVerified, r.hadSignature,
                                                r.signerKeyID.takeIf { r.signerKnown }
                                            )
                                            output = structured.body
                                            decryptedAttachments = structured.attachments
                                            val attachNote = if (structured.attachments.isEmpty()) ""
                                            else tr("d_crypto_banner_attach_suffix", structured.attachments.size)
                                            banner = when {
                                                structured.signatureVerified -> Banner.Good(
                                                    tr("d_crypto_banner_decrypted_card_verified") +
                                                        (resolveSigner(state.keys, structured.signerKeyID)
                                                            ?.let { tr("d_crypto_banner_signer_suffix", it) }
                                                            ?: "") + attachNote
                                                )
                                                structured.hasSignature -> Banner.Warn(
                                                    tr("d_crypto_banner_decrypted_card_unknown") + attachNote
                                                )
                                                else -> Banner.Info(
                                                    tr("d_crypto_banner_decrypted_card_unsigned") + attachNote
                                                )
                                            }
                                        }
                                        return@run
                                    }
                                    val result = mimeOps.decryptStructured(input, decryptPass.ifBlank { null })
                                    output = result.body
                                    decryptedAttachments = result.attachments
                                    val attachNote = if (result.attachments.isEmpty()) ""
                                    else tr("d_crypto_banner_attach_suffix", result.attachments.size)
                                    banner = when {
                                        result.signatureVerified -> Banner.Good(
                                            tr("d_crypto_banner_decrypted_verified") +
                                                (resolveSigner(state.keys, result.signerKeyID)
                                                    ?.let { tr("d_crypto_banner_signer_suffix", it) }
                                                    ?: "") + attachNote
                                        )
                                        result.hasSignature -> Banner.Warn(
                                            tr("d_crypto_banner_decrypted_unknown") +
                                                (result.signatureKeyIDRaw?.let {
                                                    tr(
                                                        "d_crypto_banner_keyid_suffix",
                                                        String.format("%016X", it)
                                                    )
                                                } ?: "") + attachNote
                                        )
                                        else -> Banner.Info(
                                            tr("d_crypto_banner_decrypted_unsigned") + attachNote
                                        )
                                    }
                                }
                            }
                        ) { Text(if (busy) tr("common_processing") else tr("decrypt_action_decrypt")) }
                    }

                    CryptoTab.SIGN -> {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(tr("d_crypto_sign_as_colon"), style = MaterialTheme.typography.titleSmall)
                            Spacer(Modifier.width(8.dp))
                            SignerPicker(signers, effectiveSigner, enabled = true) { signerFp = it }
                        }
                        OutlinedTextField(
                            value = signerPass, onValueChange = { signerPass = it },
                            label = { Text(tr("d_crypto_signer_pass_label")) },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth()
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = detachedMode, onCheckedChange = { detachedMode = it })
                            Text(tr("d_crypto_detached_toggle"))
                        }
                        Spacer(Modifier.height(10.dp))
                        BrandButton(
                            enabled = !busy && input.isNotBlank() && effectiveSigner != null,
                            onClick = {
                                val signer = effectiveSigner!!
                                if (DesktopCardOps.signsOnCard(signer)) run {
                                    // D7 — clear/detached sign on the hardware key.
                                    val ring = crypto.loadPublicKeyRing(signer.fingerprint)
                                    val pubKey = ring?.let {
                                        com.pgpony.android.crypto.card.CardSigningService.shared
                                            .signingPublicKey(it, signer.cardSigFingerprint)
                                    }
                                    if (pubKey == null) {
                                        banner = Banner.Bad(tr("d_crypto_err_card_pubkey"))
                                    } else {
                                        pendingCardOp = CardOpRequest(
                                            tr(
                                                "d_crypto_card_sign_title",
                                                signer.userID.ifBlank { tr("d_crypto_hardware_key") }
                                            )
                                        ) { session, pin ->
                                            output = if (detachedMode)
                                                com.pgpony.android.crypto.card.CardSigningService.shared
                                                    .signDetached(session, pubKey, pin,
                                                        input.toByteArray(Charsets.UTF_8), armor = true)
                                                    .toString(Charsets.UTF_8)
                                            else
                                                com.pgpony.android.crypto.card.CardSigningService.shared
                                                    .signClear(session, pubKey, pin, input)
                                            banner = Banner.Good(
                                                tr(
                                                    "d_crypto_banner_signed_card",
                                                    tr(signatureKindKey(detachedMode)), signer.userEmail
                                                )
                                            )
                                        }
                                    }
                                } else run {
                                    val ring = crypto.loadSecretKeyRing(signer.fingerprint)
                                        ?: error(tr("d_crypto_err_signer_ring"))
                                    output = if (detachedMode)
                                        SigningService.shared.signDetached(
                                            input.toByteArray(Charsets.UTF_8), ring, signerPass.ifBlank { null }
                                        ).toString(Charsets.UTF_8)
                                    else
                                        SigningService.shared.signClear(input, ring, signerPass.ifBlank { null })
                                    banner = Banner.Good(
                                        tr(
                                            "d_crypto_banner_signed",
                                            tr(signatureKindKey(detachedMode)), signer.userEmail
                                        )
                                    )
                                }
                            }
                        ) { Text(if (busy) tr("common_processing") else tr("encrypt_action_sign")) }
                    }

                    CryptoTab.VERIFY -> {
                        Text(
                            tr("d_crypto_verify_hint"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(6.dp))
                        OutlinedTextField(
                            value = detachedContent, onValueChange = { detachedContent = it },
                            label = { Text(tr("d_crypto_detached_content_label")) },
                            modifier = Modifier.fillMaxWidth().heightIn(min = 90.dp, max = 160.dp)
                        )
                        Spacer(Modifier.height(10.dp))
                        BrandButton(
                            enabled = !busy && input.isNotBlank(),
                            onClick = {
                                run {
                                    val rings = state.keys.mapNotNull { crypto.loadPublicKeyRing(it.fingerprint) }
                                    val result = when (VerifyService.shared.detectInputType(input)) {
                                        SignedInputType.CLEAR_SIGNED ->
                                            VerifyService.shared.verifyClearSigned(input, rings)
                                        SignedInputType.DETACHED_SIGNATURE -> {
                                            check(detachedContent.isNotBlank()) {
                                                tr("d_crypto_err_detached_needs_text")
                                            }
                                            VerifyService.shared.verifyDetached(
                                                input, detachedContent.toByteArray(Charsets.UTF_8), rings
                                            )
                                        }
                                        SignedInputType.ENCRYPTED ->
                                            error(tr("d_crypto_err_is_encrypted"))
                                        SignedInputType.UNKNOWN ->
                                            error(tr("d_crypto_err_no_framing"))
                                    }
                                    when (result) {
                                        is VerificationResult.Verified -> {
                                            output = result.signedContent ?: detachedContent
                                            banner = Banner.Good(
                                                tr(
                                                    "d_crypto_banner_verified",
                                                    result.signerName ?: "",
                                                    result.signerEmail ?: "?",
                                                    result.signerKeyID
                                                )
                                            )
                                        }
                                        is VerificationResult.Invalid -> banner = Banner.Bad(
                                            tr("d_crypto_banner_invalid")
                                        )
                                        is VerificationResult.UnknownSigner -> banner = Banner.Warn(
                                            tr("d_crypto_banner_unknown_signer")
                                        )
                                        is VerificationResult.Unsigned -> banner = Banner.Info(
                                            tr("d_crypto_banner_no_signature")
                                        )
                                    }
                                }
                            }
                        ) { Text(if (busy) tr("common_processing") else tr("verify_file_verify_button")) }
                    }

                    CryptoTab.FILES -> Unit   // unreachable — Files renders its own pane
                }
            }

            Spacer(Modifier.width(Spacing.Section))

            // ── Right: output ───────────────────────────────────────────
            Column(modifier = Modifier.weight(1f).fillMaxSize()) {
                banner?.let { b ->
                    BannerStrip(b)
                    Spacer(Modifier.height(Spacing.Medium))
                }
                OutlinedTextField(
                    value = output, onValueChange = { },
                    readOnly = true,
                    label = { Text(tr("d_crypto_output")) },
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    shape = RoundedCornerShape(Radius.Small),
                    modifier = Modifier.fillMaxWidth().weight(1f)
                )
                // D3c — attachments from a structured decrypt
                if (tab == CryptoTab.DECRYPT && decryptedAttachments.isNotEmpty()) {
                    Spacer(Modifier.height(Spacing.Medium))
                    SubHeading(tr("structured_result_attachments_format", decryptedAttachments.size))
                    decryptedAttachments.forEach { att ->
                        WrapRow(horizontalSpacing = Spacing.Small, verticalSpacing = Spacing.Tight) {
                            Text(
                                att.filename,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                tr("d_crypto_attachment_meta", att.contentType, att.data.size),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            TextButton(onClick = { savingAttachment = att }) { Text(tr("d_common_save_as")) }
                        }
                    }
                }

                Spacer(Modifier.height(Spacing.Medium))
                WrapRow {
                    OutlinedButton(
                        enabled = output.isNotBlank(),
                        shape = RoundedCornerShape(Radius.Small),
                        onClick = {
                            clipboard.setText(AnnotatedString(output))
                            state.status = tr("d_status_copied")
                        }
                    ) { Text(tr("d_crypto_copy_output")) }
                    if (tab == CryptoTab.ENCRYPT && output.contains("BEGIN PGP MESSAGE")) {
                        OutlinedButton(
                            onClick = { showSaveEml = true },
                            shape = RoundedCornerShape(Radius.Small)
                        ) { Text(tr("d_crypto_save_eml")) }
                    }
                    TextButton(onClick = {
                        inputs[tab] = ""; output = ""; banner = null; decryptedAttachments = emptyList()
                    }) { Text(tr("common_button_clear")) }
                }
            }
        }
    }

    // ── D3c dialogs ─────────────────────────────────────────────────────
    if (showAttachPicker) {
        MultiFileDialog { picked ->
            showAttachPicker = false
            val incoming = picked.map { it.toPath() }.filter { it !in attachments }
            attachments = attachments + incoming
        }
    }
    if (showSaveEml) {
        CryptoSaveDialog("message.eml") { file ->
            showSaveEml = false
            file?.let {
                it.writeText(mimeOps.buildEml(output))
                state.status = tr("d_status_saved", it.name)
            }
        }
    }
    savingAttachment?.let { att ->
        CryptoSaveDialog(att.filename) { file ->
            savingAttachment = null
            file?.let {
                it.writeBytes(att.data)
                state.status = tr("d_status_saved_bytes", it.name, att.data.size)
            }
        }
    }

    // D7 — the hardware-key PIN-and-run dialog. Shown whenever a card operation is pending;
    // the request's run() closure owns the actual work and the output/banner it produces.
    pendingCardOp?.let { req ->
        CardOpDialog(req) { ok, msg ->
            pendingCardOp = null
            busy = false
            if (!ok && msg != null) banner = Banner.Bad(msg)
            else if (!ok) banner = Banner.Info(tr("d_crypto_cancelled"))
        }
    }
}

/**
 * The outcome banner.
 *
 * D12 — before this, GOOD painted the whole strip in `colorScheme.primary` with white text, which
 * at the top of the output pane read as a button someone had forgotten to make clickable, and the
 * Files tab drew the same four tones as bare coloured body text instead. One shape, one place,
 * both tabs.
 *
 * The fill is a wash rather than the solid tone: a saturated full-width bar next to a monospace
 * output field is the loudest thing on the screen, and "decrypted, signature verified" does not
 * need to be the loudest thing on the screen. BAD and WARN keep saturated *text* so they still
 * separate from body copy at a glance.
 */
@Composable
private fun BannerStrip(banner: Banner) {
    val scheme = MaterialTheme.colorScheme
    val tint: Color = when (banner.tone) {
        Banner.Tone.GOOD -> Brand.Accent
        Banner.Tone.BAD -> scheme.error
        Banner.Tone.WARN -> scheme.tertiary
        Banner.Tone.NEUTRAL -> scheme.onSurfaceVariant
    }
    val ink: Color = when (banner.tone) {
        Banner.Tone.BAD -> scheme.error
        Banner.Tone.NEUTRAL -> scheme.onSurfaceVariant
        else -> scheme.onSurface
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(Radius.Small))
            .background(tint.copy(alpha = 0.12f))
    ) {
        // A 3dp full-height edge in the solid tone. It survives at a glance where a 12%-alpha
        // fill alone would not, and it costs no contrast against the text beside it.
        Box(Modifier.width(3.dp).heightIn(min = 28.dp).background(tint))
        Text(
            banner.text,
            modifier = Modifier.padding(horizontal = Spacing.Medium, vertical = Spacing.Small),
            style = MaterialTheme.typography.bodySmall,
            color = ink
        )
    }
}

/** One queued file in the Files tab: name, its folder, and a remove control. */
@Composable
private fun FileRow(path: Path, enabled: Boolean, onRemove: () -> Unit) {
    Card(
        shape = RoundedCornerShape(Radius.Small),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)
    ) {
        WrapRow(
            horizontalSpacing = Spacing.Small,
            verticalSpacing = Spacing.Tight,
            modifier = Modifier.padding(horizontal = Spacing.Medium, vertical = Spacing.Small)
        ) {
            Text(
                path.fileName.toString(),
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                path.parent?.toString() ?: "",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            TextButton(onClick = onRemove, enabled = enabled) { Text(tr("d_common_remove")) }
        }
    }
}

/** Native save dialog (AWT FileDialog, SAVE mode). */
@Composable
private fun CryptoSaveDialog(suggestedName: String, onResult: (java.io.File?) -> Unit) = AwtWindow(
    create = {
        object : FileDialog(null as Frame?, tr("common_button_save"), SAVE) {
            init { file = suggestedName }
            override fun setVisible(visible: Boolean) {
                super.setVisible(visible)
                if (visible) {
                    onResult(file?.let { java.io.File(directory, it) })
                }
            }
        }
    },
    dispose = FileDialog::dispose
)

@Composable
private fun SignerPicker(
    signers: List<PGPKeyEntity>,
    current: PGPKeyEntity?,
    enabled: Boolean,
    onPick: (String) -> Unit
) {
    var open by remember { mutableStateOf(false) }
    Column {
        OutlinedButton(onClick = { open = true }, enabled = enabled && signers.isNotEmpty()) {
            Text(current?.userID?.ifBlank { current.shortFingerprint } ?: tr("d_crypto_no_signer_available"))
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            signers.forEach { s ->
                DropdownMenuItem(
                    text = { Text("${s.userID.ifBlank { s.shortFingerprint }} · ${s.algorithm.displayName}") },
                    onClick = { onPick(s.fingerprint); open = false }
                )
            }
        }
    }
}

/** Native multi-select file picker (AWT FileDialog with multiple mode). */
@Composable
private fun MultiFileDialog(onResult: (List<java.io.File>) -> Unit) = AwtWindow(
    create = {
        object : FileDialog(null as Frame?, tr("encrypt_bundle_add_files"), LOAD) {
            init { isMultipleMode = true }
            override fun setVisible(visible: Boolean) {
                super.setVisible(visible)
                if (visible) {
                    onResult(files?.toList().orEmpty())
                }
            }
        }
    },
    dispose = FileDialog::dispose
)

/**
 * Which of the two signature shapes the Sign tab just produced. A key rather than a resolved
 * string so the caller can nest it inside the banner's own `tr()` and both halves resolve in the
 * same language on the same frame.
 */
private fun signatureKindKey(detached: Boolean): String =
    if (detached) "encrypt_sign_detached_label" else "d_crypto_clear_signed"

private fun fileBanner(results: List<FileCryptoOps.FileOutcome>): Banner {
    val ok = results.count { it.ok }
    return if (ok == results.size) Banner.Good(tr("d_crypto_files_done", ok, results.size))
    else Banner.Warn(tr("d_crypto_files_partial", ok, results.size))
}

// ── D7 Files card batches — one PIN entry, one card session, whole list ─────

/** Detached-sign every file on the card. */
private suspend fun buildCardFileSign(
    state: DesktopState,
    fileOps: FileCryptoOps,
    files: List<java.nio.file.Path>,
    signer: PGPKeyEntity,
    armor: Boolean,
    onResult: (List<FileCryptoOps.FileOutcome>) -> Unit
): CardOpRequest? {
    val ring = state.repository.loadPublicKeyRing(signer.fingerprint) ?: return null
    val pubKey = com.pgpony.android.crypto.card.CardSigningService.shared
        .signingPublicKey(ring, signer.cardSigFingerprint)
    return CardOpRequest(
        tr("d_crypto_card_sign_files", files.size, signer.userID.ifBlank { tr("d_crypto_hardware_key") })
    ) { session, pin ->
        val outcomes = files.map { fileOps.signFileDetachedWithCard(it, session, pubKey, pin, armor) }
        onResult(outcomes)
    }
}

/** Encrypt every file to the recipients, signature leg on the card. */
private suspend fun buildCardFileEncrypt(
    state: DesktopState,
    fileOps: FileCryptoOps,
    files: List<java.nio.file.Path>,
    recipients: Set<String>,
    signer: PGPKeyEntity,
    armor: Boolean,
    onResult: (List<FileCryptoOps.FileOutcome>) -> Unit
): CardOpRequest? {
    val ring = state.repository.loadPublicKeyRing(signer.fingerprint) ?: return null
    val pubKey = com.pgpony.android.crypto.card.CardSigningService.shared
        .signingPublicKey(ring, signer.cardSigFingerprint)
    return CardOpRequest(
        tr(
            "d_crypto_card_sign_encrypt_files",
            files.size, signer.userID.ifBlank { tr("d_crypto_hardware_key") }
        )
    ) { session, pin ->
        val outcomes = files.map {
            fileOps.encryptFileWithCardSigner(it, recipients, session, pin, pubKey, armor)
        }
        onResult(outcomes)
    }
}

/**
 * Decrypt a batch where at least one file is addressed to a paired card key. Card-addressed
 * files decrypt on the hardware inside one session; the rest fall back to software. Returns
 * null when NO file needs the card (the caller then runs the all-software path).
 */
private suspend fun buildCardFileDecrypt(
    state: DesktopState,
    fileOps: FileCryptoOps,
    files: List<java.nio.file.Path>,
    passphrase: String?,
    onResult: (List<FileCryptoOps.FileOutcome>) -> Unit
): CardOpRequest? {
    val repo = state.repository
    val matches = files.associateWith { f ->
        runCatching {
            DesktopCardOps.matchCardDecryptKey(fileOps.encryptedBytesForCard(f), repo)
        }.getOrNull()
    }
    if (matches.values.none { it != null }) return null
    val cardKeyName = matches.values.firstOrNull { it != null }?.entity
        ?.userID?.ifBlank { tr("d_crypto_hardware_key") } ?: tr("d_crypto_hardware_key")
    return CardOpRequest(
        tr("d_crypto_card_decrypt_files", matches.values.count { it != null }, cardKeyName)
    ) { session, pin ->
        val outcomes = files.map { f ->
            val m = matches[f]
            if (m != null) fileOps.decryptFileWithCard(f, session, m.ring, pin)
            else fileOps.decryptFile(f, passphrase)
        }
        onResult(outcomes)
    }
}

/** Resolve a signature's long key ID against the keyring for display. */
private fun resolveSigner(keys: List<PGPKeyEntity>, signerKeyID: String?): String? {
    if (signerKeyID == null) return null
    val match = keys.firstOrNull { it.longKeyId.equals(signerKeyID, ignoreCase = true) }
        ?: keys.firstOrNull { it.fingerprint.endsWith(signerKeyID, ignoreCase = true) }
        ?: keys.firstOrNull { it.fingerprint.startsWith(signerKeyID, ignoreCase = true) }
    return match?.userID?.ifBlank { null } ?: signerKeyID
}
