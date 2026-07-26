// AppLinks.kt
// PGPony Desktop — outbound links from the Settings screen: the project's own repo and site, and
// the rest of the NorseHorse app family.
//
// Three things live here that nothing else in the app needed until now:
//
//  1. openUri() — a browser handoff. Android has Intent.ACTION_VIEW; the JVM has java.awt.Desktop,
//     which is present but NOT always functional (a Linux box with no XDG portal, a headless CI
//     run), so every path is guarded and a failure degrades to putting the URL on the clipboard
//     rather than to a stack trace in the user's face.
//
//  2. appIcon() — the six PNGs under resources/icons/, decoded once and cached. They are the real
//     App Store icons, downscaled to 128px from each app's 1024px AppIcon asset.
//
//  3. The link/app row composables, which are shared between the About and "More from" sections.
//
// SECURITY: openUri() is only ever called with the hardcoded constants in this file. Nothing here
// takes a URL from a key, a keyserver entry, a backup, or any other attacker-influenced source —
// handing java.awt.Desktop an untrusted URI is how you get a `file:` or `smb:` surprise.

package com.pgpony.desktop

import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.toPainter
import androidx.compose.ui.unit.dp
import java.awt.Desktop
import java.io.File
import java.net.URI
import java.util.Locale
import javax.imageio.ImageIO

// ── The link targets ───────────────────────────────────────────────────

object Links {
    /**
     * Public from the 1.0 release (D13), which is what `d_settings_about_repo_note` has always
     * promised in all six locales — the note reads correctly either side of that switch, so it
     * needed no change when the repo actually went up.
     */
    const val REPO = "https://github.com/norsehorse-dev/PGPonyDesktop"
    const val ISSUES = "$REPO/issues"
    const val WEBSITE = "https://pgpony.app"
}

/**
 * One entry in the "More from NorseHorse" list.
 *
 * [title] and [platforms] are deliberately NOT resource keys: they are product names and OS names,
 * which read identically in all six languages and would only invite a translator to invent
 * "RelaisPoney". Only [descriptionKey] — the sentence explaining what the app does — is translated.
 *
 * [icon] names a PNG under `resources/icons/`, downscaled from that app's own AppIcon asset.
 */
data class PonyApp(
    val title: String,
    val url: String,
    val descriptionKey: String,
    val platforms: String,
    val icon: String
)

object PonyApps {
    /**
     * Ordered by how close each app sits to what someone in a PGP keyring app is already doing:
     * the mobile PGPony first (same keys, same engine), then the two that also speak OpenPGP,
     * then key backup, then transport, then the ephemeral one.
     */
    val ALL: List<PonyApp> = listOf(
        PonyApp(
            title = "PGPony",
            url = "https://pgpony.app",
            descriptionKey = "d_app_pgpony_desc",
            // Including the three desktop OSes: as of 1.0 this app IS the desktop half of that
            // list, so the row describes the whole PGPony family rather than just the phone apps.
            platforms = "iPhone · Android · macOS · Windows · Linux",
            icon = "pgpony"
        ),
        PonyApp(
            title = "CarrierPony",
            url = "https://carrierpony.com",
            descriptionKey = "d_app_carrierpony_desc",
            platforms = "iPhone · Android",
            icon = "carrierpony"
        ),
        PonyApp(
            title = "AgePony",
            url = "https://agepony.com",
            descriptionKey = "d_app_agepony_desc",
            platforms = "iPhone · Android",
            icon = "agepony"
        ),
        PonyApp(
            title = "QuorumPony",
            url = "https://quorumpony.com",
            descriptionKey = "d_app_quorumpony_desc",
            platforms = "iPhone",
            icon = "quorumpony"
        ),
        PonyApp(
            title = "RelayPony",
            url = "https://relaypony.app",
            descriptionKey = "d_app_relaypony_desc",
            platforms = "iPhone · Android · macOS · Windows · Linux",
            icon = "relaypony"
        ),
        PonyApp(
            title = "BurnPony",
            url = "https://burnpony.app",
            descriptionKey = "d_app_burnpony_desc",
            platforms = "iPhone",
            icon = "burnpony"
        )
    )
}

// ── Opening things ─────────────────────────────────────────────────────

/**
 * Hand [url] to the user's browser.
 *
 * `Desktop.isDesktopSupported()` is the documented gate, but it is not sufficient: it answers "is
 * there an AWT desktop peer", not "can this machine browse". A GNOME session without
 * xdg-desktop-portal answers yes and then throws from [Desktop.browse], so the real work is in the
 * catch — fall back to the platform's own opener command, and if even that fails, put the URL on
 * the clipboard and say so. The user always ends up able to reach the page.
 */
fun openUri(url: String, state: DesktopState?) {
    if (browse(url)) return
    if (shellOpen(url)) return
    DesktopClipboard.copy(url, secret = false)
    state?.status = tr("d_status_open_failed", url)
}

/**
 * Reveal [file] in Finder / Explorer / the Linux file manager. Same escalation as [openUri]; the
 * fallback copies the path rather than the URL, because a path is what the user would paste into
 * a terminal.
 */
fun openFolder(file: File, state: DesktopState?) {
    val ok = runCatching {
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
            Desktop.getDesktop().open(file); true
        } else false
    }.getOrDefault(false) || shellOpen(file.absolutePath)

    if (!ok) {
        DesktopClipboard.copy(file.absolutePath, secret = false)
        state?.status = tr("d_status_open_failed", file.absolutePath)
    }
}

private fun browse(url: String): Boolean = runCatching {
    if (!Desktop.isDesktopSupported()) return false
    val desktop = Desktop.getDesktop()
    if (!desktop.isSupported(Desktop.Action.BROWSE)) return false
    desktop.browse(URI(url))
    true
}.getOrDefault(false)

/**
 * The per-OS opener, used when AWT declines or throws. `open` and `xdg-open` both take a URL or a
 * path; Windows needs the `rundll32` shim because `start` is a cmd.exe builtin, not an executable.
 */
private fun shellOpen(target: String): Boolean {
    val os = System.getProperty("os.name").orEmpty().lowercase(Locale.ROOT)
    val cmd = when {
        os.contains("mac") -> arrayOf("open", target)
        os.contains("win") -> arrayOf("rundll32", "url.dll,FileProtocolHandler", target)
        else -> arrayOf("xdg-open", target)
    }
    return runCatching { ProcessBuilder(*cmd).start(); true }.getOrDefault(false)
}

// ── Icons ──────────────────────────────────────────────────────────────

/**
 * Decode `resources/icons/<name>.png` once and keep it.
 *
 * ImageIO rather than any of the Compose resource loaders on purpose: `painterResource(String)` and
 * `loadImageBitmap` have both been reshuffled between Compose Multiplatform releases as the
 * `components.resources` library took over, whereas `BufferedImage.toPainter()` has been the same
 * two-line desktop bridge since Compose Desktop 1.0. A missing or corrupt file yields null and the
 * row draws its placeholder — an icon is decoration, never a reason to fail a screen.
 */
private val iconCache = HashMap<String, Painter?>()

@Synchronized
fun appIcon(name: String): Painter? = iconCache.getOrPut(name) {
    runCatching {
        val stream = PonyApps::class.java.getResourceAsStream("/icons/$name.png") ?: return@runCatching null
        stream.use { ImageIO.read(it) }?.toPainter()
    }.getOrNull()
}

// ── Rows ───────────────────────────────────────────────────────────────

/**
 * A one-line link: label on the left, the bare host/path on the right, the whole row clickable.
 * The URL is shown without its scheme — `github.com/norsehorse-dev/PGPonyDesktop` is what the user
 * would recognise and retype; `https://` is noise in a settings list.
 */
@Composable
fun LinkRow(labelKey: String, url: String, state: DesktopState) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable { openUri(url, state) }
            .padding(vertical = 5.dp)
    ) {
        Icon(
            // AutoMirrored: the glyph's arrow points out of the box, so it flips under an RTL
            // layout. None of the six locales is RTL today, but the plain Filled variant is
            // deprecated precisely to stop this from becoming a bug when one is.
            Icons.AutoMirrored.Filled.OpenInNew,
            contentDescription = null,
            modifier = Modifier.size(16.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(Modifier.width(8.dp))
        Text(
            tr(labelKey),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary
        )
        Spacer(Modifier.width(10.dp))
        Text(
            url.removePrefix("https://"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

/** Icon + name + platforms + one-line description, the whole card opening [app]'s site. */
@Composable
fun AppLinkRow(app: PonyApp, state: DesktopState) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
            .clickable { openUri(app.url, state) }
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)
        ) {
            val painter = appIcon(app.icon)
            if (painter != null) {
                Image(
                    painter = painter,
                    contentDescription = null,
                    modifier = Modifier.size(40.dp).clip(RoundedCornerShape(9.dp))
                )
            } else {
                // Same footprint as the icon so a failed decode doesn't reflow the row.
                Box(Modifier.size(40.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(app.title, style = MaterialTheme.typography.titleSmall)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        app.platforms,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(Modifier.height(2.dp))
                Text(
                    tr(app.descriptionKey),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(Modifier.width(10.dp))
            Text(
                app.url.removePrefix("https://"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary
            )
        }
    }
}
