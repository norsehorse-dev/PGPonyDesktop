// GenerateKeyDialog.kt
// PGPony Desktop — D2b key generation. Mirrors the Android generate sheet's field set (name,
// email, algorithm, passphrase) with the full 4.0.0 algorithm roster — including both
// post-quantum composites, which the vendored engine generates the same way Android does.
// D11b — localized. The algorithm NAMES are not keys: algo.displayName comes out of the
// vendored KeyAlgorithm enum and reads "Ed25519" / "RSA 4096" in every language, because
// those are spec names. The one-line hints under them are keys. The field labels and the
// buttons are reused from the phone's generate sheet (keyring_generate_*) — same fields,
// same wording, already translated six ways.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.crypto.KeyAlgorithm

/** The generatable roster — the exact branches of the vendored generateKeyPair. */
private val GENERATABLE = listOf(
    KeyAlgorithm.ED25519_CV25519,
    KeyAlgorithm.V6_ED25519,
    KeyAlgorithm.MLKEM768_X25519_V6,
    KeyAlgorithm.MLKEM768_X25519_LIBREPGP,
    KeyAlgorithm.RSA_4096,
    KeyAlgorithm.RSA_2048
)

private fun hintFor(algo: KeyAlgorithm): String = when (algo) {
    KeyAlgorithm.ED25519_CV25519 -> tr("d_gen_hint_ed25519")
    KeyAlgorithm.V6_ED25519 -> tr("d_gen_hint_v6")
    KeyAlgorithm.MLKEM768_X25519_V6 -> tr("d_gen_hint_pq_v6")
    KeyAlgorithm.MLKEM768_X25519_LIBREPGP -> tr("d_gen_hint_pq_librepgp")
    KeyAlgorithm.RSA_4096 -> tr("d_gen_hint_rsa4096")
    KeyAlgorithm.RSA_2048 -> tr("d_gen_hint_rsa2048")
    else -> ""
}

@Composable
fun GenerateKeyDialog(
    busy: Boolean,
    onDismiss: () -> Unit,
    onGenerate: (name: String, email: String, algorithm: KeyAlgorithm, passphrase: String?) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var algorithm by remember { mutableStateOf(KeyAlgorithm.ED25519_CV25519) }
    var passphrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }

    val emailOk = email.contains("@") && email.contains(".")
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
                    .heightIn(max = 520.dp)
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
                    enabled = !busy, isError = email.isNotBlank() && !emailOk,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(Modifier.height(14.dp))
                Text(tr("keyring_generate_algorithm_label"), style = MaterialTheme.typography.titleSmall)
                GENERATABLE.forEach { algo ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(
                            selected = algorithm == algo,
                            onClick = { algorithm = algo },
                            enabled = !busy
                        )
                        Column {
                            // Spec name (Ed25519, RSA 4096) — identical in every language.
                            Text(algo.displayName, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                hintFor(algo),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
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
                    onGenerate(name.trim(), email.trim(), algorithm, passphrase.ifBlank { null })
                },
                enabled = canGenerate
            ) { Text(if (busy) tr("d_common_working") else tr("keyring_generate_button")) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !busy) { Text(tr("common_button_cancel")) }
        }
    )
}
