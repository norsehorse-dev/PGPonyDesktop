// GenerateKeyDialog.kt
// PGPony Desktop key generation. D2b mirrored the Android generate sheet's field set; 3.0.0
// (stage 3, plan 4.1) brings it to Android 4.6.1:
//   * the picker is Android's KeygenAlgorithmPicker: Classical and Post-Quantum groups, then the
//     collapsed Interop (the three ML-KEM-768+X25519 wire shapes: v6, v4, v5) and Advanced (RSA,
//     the LibrePGP ML-KEM-1024 and brainpoolP256r1 forms) groups, the lists coming straight from
//     the vendored KeyAlgorithm so the two apps cannot drift;
//   * "Limited app support" on every post-quantum choice, and Android's captions;
//   * the email is optional (a name-only User ID);
//   * an optional SSH authentication subkey (Android 4.6.0 item 16);
//   * the granular composer (Android 4.5.0 item 7): a v6 Ed25519 primary, its default X25519
//     encryption subkey kept or dropped, and any subkeys chosen from the Add Subkey list;
//   * an expiration (Android's presets, two years by default); desktop keys used to never expire.
// Algorithm NAMES are spec names from the vendored enum and read the same in every language.

package com.pgpony.desktop

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.AlertDialog
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.KeyAlgorithm
import java.util.prefs.Preferences

/** Android ExpirationOption: the same presets, the same 365.25-day year. */
enum class KeygenExpiry(val seconds: Long?) {
    ONE_YEAR((365.25 * 24 * 60 * 60).toLong()),
    TWO_YEARS((2 * 365.25 * 24 * 60 * 60).toLong()),
    FIVE_YEARS((5 * 365.25 * 24 * 60 * 60).toLong()),
    NEVER(null)
}

/** Everything the dialog decided. [granularSubkeys] is used only when [granular]. */
data class KeygenRequest(
    val name: String,
    val email: String,
    val algorithm: KeyAlgorithm,
    val passphrase: String?,
    val expirationSeconds: Long?,
    val sshAuth: Boolean = false,
    val granular: Boolean = false,
    val includeDefaultEncryption: Boolean = true,
    val granularSubkeys: List<AddSubkeyChoice> = emptyList()
)

/** Android 4.5.0 item 8: offer to publish a freshly generated key. On by default. */
object KeygenPrefs {
    const val KEY_OFFER_PUBLISH = "offer_publish_after_keygen"

    internal var prefsOverride: Preferences? = null
    private fun prefs(): Preferences = prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun offerPublish(): Boolean = prefs().getBoolean(KEY_OFFER_PUBLISH, true)
    fun setOfferPublish(on: Boolean) { prefs().putBoolean(KEY_OFFER_PUBLISH, on); runCatching { prefs().flush() } }
}

private fun captionFor(algorithm: KeyAlgorithm): String = when {
    algorithm == KeyAlgorithm.MLDSA87_ED448_V6 -> tr("keyring_generate_algorithm_caption_pqc_sign_87")
    algorithm.isCompositeSign -> tr("keyring_generate_algorithm_caption_pqc_sign")
    algorithm == KeyAlgorithm.MLKEM768_X25519_V4 -> tr("keyring_generate_algorithm_caption_pqc_v4")
    algorithm.isComposite && algorithm.isV6 -> tr("keyring_generate_algorithm_caption_pqc_ietf")
    algorithm.isComposite -> tr("keyring_generate_algorithm_caption_pqc_librepgp")
    algorithm.isV6 -> tr("keyring_generate_algorithm_caption_v6")
    algorithm == KeyAlgorithm.ED25519_CV25519 -> tr("keyring_generate_algorithm_caption_ed25519")
    else -> tr("keyring_generate_algorithm_caption_rsa")
}

private fun expiryLabel(e: KeygenExpiry): String = when (e) {
    KeygenExpiry.ONE_YEAR -> tr("expiration_one_year")
    KeygenExpiry.TWO_YEARS -> tr("expiration_two_years")
    KeygenExpiry.FIVE_YEARS -> tr("expiration_five_years")
    KeygenExpiry.NEVER -> tr("expiration_never")
}

@Composable
fun GenerateKeyDialog(
    busy: Boolean,
    onDismiss: () -> Unit,
    onGenerate: (KeygenRequest) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var algorithm by remember { mutableStateOf(KeyAlgorithm.ED25519_CV25519) }
    var expiry by remember { mutableStateOf(KeygenExpiry.TWO_YEARS) }
    var sshAuth by remember { mutableStateOf(false) }
    var granular by remember { mutableStateOf(false) }
    var includeDefault by remember { mutableStateOf(true) }
    val granularSubkeys = remember { mutableStateListOf<AddSubkeyChoice>() }
    var passphrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }

    // Android item 3: the email is optional; a non-blank one still has to look like an address.
    val emailOk = email.isBlank() || email.contains("@")
    val passMatch = passphrase == confirm
    val canGenerate = !busy && name.isNotBlank() && emailOk && passMatch

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = {
            Text(if (busy) tr("keyring_generate_button_in_progress") else tr("keyring_generate_title"))
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 560.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    label = { Text(tr("keyring_generate_name_label")) }, singleLine = true,
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = email, onValueChange = { email = it },
                    label = { Text(tr("keyring_generate_email_label")) }, singleLine = true,
                    enabled = !busy, isError = !emailOk,
                    modifier = Modifier.fillMaxWidth()
                )
                if (!emailOk) {
                    Text(tr("keyring_error_email_invalid"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }

                Spacer(Modifier.height(14.dp))
                if (!granular) {
                    AlgorithmPicker(algorithm, enabled = !busy) { algorithm = it }
                    Spacer(Modifier.height(10.dp))
                    CheckRow(
                        checked = sshAuth, enabled = !busy, onChange = { sshAuth = it },
                        title = tr("keyring_generate_ssh_auth_toggle"),
                        subtitle = tr("keyring_generate_ssh_auth_caption")
                    )
                }

                // Android item 7 (#55): the granular composer.
                CheckRow(
                    checked = granular, enabled = !busy, onChange = { granular = it },
                    title = tr("keyring_generate_granular_toggle"), subtitle = null
                )
                if (granular) {
                    CheckRow(
                        checked = includeDefault, enabled = !busy, onChange = { includeDefault = it },
                        title = tr("keyring_generate_granular_include_default"), subtitle = null
                    )
                    granularSubkeys.forEachIndexed { i, choice ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(subkeyChoiceLabel(choice), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                            IconButton(onClick = { granularSubkeys.removeAt(i) }, enabled = !busy) {
                                Icon(Icons.Filled.Close, contentDescription = tr("key_detail_notations_remove_row"))
                            }
                        }
                    }
                    var menuOpen by remember { mutableStateOf(false) }
                    Box {
                        OutlinedButton(onClick = { menuOpen = true }, enabled = !busy) {
                            Text(tr("keyring_generate_granular_add_subkey"))
                        }
                        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                            (AddSubkeyChoice.classicalFor(isV6 = true) + AddSubkeyChoice.postQuantumFor(isV6 = true)).forEach { choice ->
                                DropdownMenuItem(
                                    text = { Text(subkeyChoiceLabel(choice)) },
                                    onClick = { granularSubkeys.add(choice); menuOpen = false }
                                )
                            }
                        }
                    }
                }

                Spacer(Modifier.height(14.dp))
                Text(tr("keyring_generate_expiration_label"), style = MaterialTheme.typography.titleSmall)
                WrapRow {
                    KeygenExpiry.entries.forEach { e ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(selected = expiry == e, onClick = { expiry = e }, enabled = !busy)
                            Text(expiryLabel(e), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }

                Spacer(Modifier.height(14.dp))
                OutlinedTextField(
                    value = passphrase, onValueChange = { passphrase = it },
                    label = { Text(tr("keyring_generate_passphrase_label")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = confirm, onValueChange = { confirm = it },
                    label = { Text(tr("keyring_generate_passphrase_confirm_label")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !busy, isError = confirm.isNotBlank() && !passMatch,
                    modifier = Modifier.fillMaxWidth()
                )
                if (passphrase.isBlank()) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        tr("d_gen_no_passphrase_warning"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onGenerate(
                        KeygenRequest(
                            name = name.trim(),
                            email = email.trim(),
                            algorithm = if (granular) KeyAlgorithm.V6_ED25519 else algorithm,
                            passphrase = passphrase.ifBlank { null },
                            expirationSeconds = expiry.seconds,
                            sshAuth = sshAuth && !granular,
                            granular = granular,
                            includeDefaultEncryption = includeDefault,
                            granularSubkeys = granularSubkeys.toList()
                        )
                    )
                },
                enabled = canGenerate
            ) { Text(if (busy) tr("d_common_working") else tr("keyring_generate_button")) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !busy) { Text(tr("common_button_cancel")) }
        }
    )
}

/** Android KeygenAlgorithmPicker, as radio rows. */
@Composable
private fun AlgorithmPicker(selected: KeyAlgorithm, enabled: Boolean, onSelect: (KeyAlgorithm) -> Unit) {
    var interopOpen by remember { mutableStateOf(selected in KeyAlgorithm.generatableInterop) }
    var advancedOpen by remember { mutableStateOf(selected in KeyAlgorithm.generatableAdvanced) }

    Text(tr("keyring_generate_algorithm_label"), style = MaterialTheme.typography.titleSmall)
    GroupLabel(tr("keyring_generate_algorithm_group_classical"))
    KeyAlgorithm.generatableClassical.forEach { AlgorithmRow(it, selected, enabled, onSelect) }
    GroupLabel(tr("keyring_generate_algorithm_group_pqc"))
    KeyAlgorithm.generatablePostQuantum.forEach { AlgorithmRow(it, selected, enabled, onSelect) }
    Expander(tr("keyring_generate_algorithm_group_interop"), interopOpen) { interopOpen = !interopOpen }
    if (interopOpen) KeyAlgorithm.generatableInterop.forEach { AlgorithmRow(it, selected, enabled, onSelect) }
    Expander(tr("keyring_generate_algorithm_group_advanced"), advancedOpen) { advancedOpen = !advancedOpen }
    if (advancedOpen) KeyAlgorithm.generatableAdvanced.forEach { AlgorithmRow(it, selected, enabled, onSelect) }

    Spacer(Modifier.height(6.dp))
    Text(captionFor(selected), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    if (selected.isPostQuantum) {
        Spacer(Modifier.height(4.dp))
        Text(
            tr("keyring_generate_algorithm_experimental_note"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.tertiary
        )
    }
}

@Composable
private fun GroupLabel(text: String) {
    Spacer(Modifier.height(6.dp))
    Text(text, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun Expander(text: String, open: Boolean, onToggle: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().clickable(onClick = onToggle).padding(vertical = 6.dp)
    ) {
        Icon(
            if (open) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.width(4.dp))
        Text(text, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun AlgorithmRow(algo: KeyAlgorithm, selected: KeyAlgorithm, enabled: Boolean, onSelect: (KeyAlgorithm) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        RadioButton(selected = selected == algo, onClick = { onSelect(algo) }, enabled = enabled)
        Column {
            Text(algo.displayName, style = MaterialTheme.typography.bodyMedium)
            // Android 4.6.0 item 13: set expectations on every post-quantum choice.
            if (algo.isPostQuantum) {
                Text(
                    tr("keyring_generate_algorithm_experimental"),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.tertiary
                )
            }
        }
    }
}

@Composable
private fun CheckRow(checked: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit, title: String, subtitle: String?) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChange, enabled = enabled)
        Column {
            Text(title, style = MaterialTheme.typography.bodyMedium)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
