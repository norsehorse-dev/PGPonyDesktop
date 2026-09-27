// DestructiveGuard.kt
// PGPony Desktop 3.0.0 (plan 3.2, Android 4.5.0 item 27 and 4.5.1 item 8).
//
// Android puts delete key, remove subkey, remove User ID and clear all data behind device
// authentication, and offers a switch that hides them outright. Desktop has no portable device
// authentication, so the decision for 3.0.0 (plan Q3) is a typed confirmation: with "Protect
// destructive actions" on (the default), each of those actions asks for the word DELETE. "Hide
// destructive actions" (off by default) removes them from the app; revoke stays.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import java.util.prefs.Preferences

object DestructiveGuard {

    const val KEY_PROTECT = "protect_destructive_actions"
    const val KEY_HIDE = "hide_destructive_actions"

    /** Test hook: a scratch node instead of the real one. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences = prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun protect(): Boolean = prefs().getBoolean(KEY_PROTECT, true)
    fun setProtect(on: Boolean) { prefs().putBoolean(KEY_PROTECT, on); runCatching { prefs().flush() } }

    fun hidden(): Boolean = prefs().getBoolean(KEY_HIDE, false)
    fun setHidden(on: Boolean) { prefs().putBoolean(KEY_HIDE, on); runCatching { prefs().flush() } }

    /** The word the user types. Kept as Android's vendored string so it matches the phone. */
    fun word(): String = tr("settings_data_clear_type_word")

    fun accepts(typed: String): Boolean = !protect() || typed.trim() == word()
}

/**
 * A destructive confirmation: [body] above, the typed-word field when protection is on, and a
 * confirm button that stays disabled until the word matches. [extra] renders between the body
 * and the field (a backup line, a revoke-instead button).
 */
@Composable
fun DestructiveConfirmDialog(
    title: String,
    body: String,
    confirmLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
    extra: @Composable () -> Unit = {}
) {
    var typed by remember { mutableStateOf("") }
    val protect = remember { DestructiveGuard.protect() }
    BrandDialog(
        onDismissRequest = onDismiss,
        title = title,
        destructive = true,
        content = {
            Column {
                Text(body)
                extra()
                if (protect) {
                    Spacer(Modifier.height(Spacing.Medium))
                    OutlinedTextField(
                        value = typed,
                        onValueChange = { typed = it },
                        singleLine = true,
                        label = { Text(tr("settings_data_clear_type_label_format", DestructiveGuard.word())) },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        },
        confirmButton = {
            TextButton(enabled = DestructiveGuard.accepts(typed), onClick = onConfirm) { Text(confirmLabel) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("common_button_cancel")) } }
    )
}
