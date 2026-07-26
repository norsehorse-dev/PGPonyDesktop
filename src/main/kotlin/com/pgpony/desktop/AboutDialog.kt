// AboutDialog.kt
// PGPony Desktop — D12 batch 3: the About dialog.
//
// The fourth of D12's four icon surfaces (window + dock, tray, nav rail header, and here). It is
// also the answer to a question the desktop build has not had one for since D1: a phone user who
// wants to know what they are running taps through to a store listing, and a desktop user has
// nowhere to tap. So this carries the mark, the version, the paste-ready runtime line a bug report
// will ask for, the three project links, and the rest of the app family.
//
// Everything here already existed in Settings → About; this does not duplicate that section so
// much as give it a second, findable door. The two share their strings and their link rows, so
// wording only ever has to change in one place.
//
// The dialog opens from Help → About PGPony in the menu bar. Compose Desktop cannot populate
// macOS's application menu, so a Help menu is the one spot that behaves the same on all three
// operating systems.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * The About modal.
 *
 * Both axes are bounded on purpose. The width is pinned because the content is a mix of a
 * fixed-size mark, wrapping prose and a monospace runtime string — left to size itself the dialog
 * would be as wide as the longest German sentence in it. The height is capped and made scrollable
 * because the family list grows every time NorseHorse ships an app, and an About box that runs off
 * the bottom of a 13-inch screen is worse than one that scrolls.
 */
@Composable
fun AboutDialog(state: DesktopState, onDismiss: () -> Unit) {
    BrandDialog(
        onDismissRequest = onDismiss,
        title = tr("d_about_title"),
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(tr("common_button_close")) }
        }
    ) {
        Column(
            modifier = Modifier
                .width(440.dp)
                .heightIn(max = 460.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                BrandMark(size = 64.dp)
                Spacer(Modifier.width(Spacing.Large))
                Column {
                    // "PGPony Desktop" is the product name — a literal, not a key, the same call
                    // the window title and the tray tooltip make.
                    Text(
                        "PGPony Desktop",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.SemiBold,
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
            BrandRule()
            Spacer(Modifier.height(Spacing.Large))

            Text(
                tr("d_settings_about_note"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(Modifier.height(Spacing.Medium))
            // The first thing anyone will be asked for in a bug report, and the last thing a user
            // can be expected to assemble on their own.
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

            Spacer(Modifier.height(Spacing.Large))
            SubHeading(tr("d_about_links"))
            LinkRow("d_settings_about_repo", Links.REPO, state)
            LinkRow("d_settings_about_issues", Links.ISSUES, state)
            LinkRow("d_settings_about_website", Links.WEBSITE, state)

            Spacer(Modifier.height(Spacing.Large))
            SubHeading(tr("d_settings_section_apps"))
            PonyApps.ALL.forEach { app -> AppLinkRow(app, state) }
        }
    }
}
