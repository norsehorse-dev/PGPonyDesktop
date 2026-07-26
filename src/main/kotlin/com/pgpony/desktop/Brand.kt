package com.pgpony.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * D12 — the brand layer: the PGPony gradient, the spacing and radius scales, and the handful of
 * widgets built on top of them.
 *
 * This is deliberately a NEW file rather than an addition to [Theme.kt]. Theme.kt's two
 * ColorSchemes are a verbatim port of the Android app's `AppTheme.kt` and are held at parity
 * with it — a desktop-only accent belongs beside that file, not inside it. Everything here is
 * additive: nothing in Brand.kt changes what `MaterialTheme.colorScheme` resolves to, so a
 * screen that has not been restyled yet keeps looking exactly as it did.
 *
 * Only stable Compose APIs are used, per the project rule that no source file carries `@OptIn`.
 */
object Brand {

    /**
     * The two ends of the PGPony gradient, taken from the Android adaptive icon's background
     * (`res/drawable/ic_launcher_background.xml`, a linear gradient across the 108dp tile from
     * top-left to bottom-right). The app icon, the nav rail and the primary buttons therefore
     * all carry the same two colors, which is the whole point of the exercise: the mark in the
     * Dock and the button under the cursor are visibly the same brand.
     */
    val GradientStart: Color = Color(0xFF4B69F1)
    val GradientEnd: Color = Color(0xFFB42DEB)

    /** The midpoint, for the places that want one flat brand color (borders, focus rings). */
    val Accent: Color = Color(0xFF7F4BEE)

    /**
     * Top-left to bottom-right, matching the icon.
     *
     * `Offset.Infinite` is Compose's "however big the thing being drawn turns out to be", so the
     * same brush is correct on a 40dp button and on a full-height rail without either one having
     * to measure itself first.
     */
    fun gradient(): Brush =
        Brush.linearGradient(listOf(GradientStart, GradientEnd), Offset.Zero, Offset.Infinite)

    /** Straight down. For tall narrow surfaces where the diagonal reads as a stripe. */
    fun gradientVertical(): Brush = Brush.verticalGradient(listOf(GradientStart, GradientEnd))

    /**
     * The gradient at low opacity over the current surface — for card headers and selected rows
     * that want a hint of brand without turning into a button. Alpha stays deliberately low: the
     * scheme's `onSurface` has to stay legible on top of it in both light and dark.
     */
    fun gradientWash(alpha: Float = 0.12f): Brush = Brush.linearGradient(
        listOf(GradientStart.copy(alpha = alpha), GradientEnd.copy(alpha = alpha)),
        Offset.Zero,
        Offset.Infinite
    )
}

/**
 * The spacing scale.
 *
 * Before D12 the screens used bare `6.dp` / `8.dp` / `14.dp` literals chosen one call site at a
 * time, which is why the same visual relationship (label to field, button to button) had three
 * different gaps depending on which file you were in. These are the values those literals
 * clustered around, rounded onto a 4dp grid.
 */
object Spacing {
    /** Between an icon and the word next to it. */
    val Tight: Dp = 4.dp

    /** Between two controls that belong to the same thought — sibling buttons, chips in a row. */
    val Small: Dp = 8.dp

    /** The default gap inside a group: label to field, row to row. */
    val Medium: Dp = 12.dp

    /** Between groups inside one card or dialog section. */
    val Large: Dp = 16.dp

    /** Between sections. Also the standard inset from a dialog or screen edge. */
    val Section: Dp = 24.dp

    /** Screen-level breathing room around the whole content column. */
    val Screen: Dp = 32.dp
}

/** Corner radii. Small for pills and chips, Medium for cards, Large for the icon mark. */
object Radius {
    val Small: Dp = 6.dp
    val Medium: Dp = 12.dp
    val Large: Dp = 18.dp
}

/**
 * The app mark, at whatever size the caller asks for.
 *
 * Reads the generated `icons/pgpony_512.png` through the existing [appIcon] cache, so the file is
 * decoded once for the whole process no matter how many places draw it. If the resource is
 * missing the widget still renders — a gradient tile with a padlock glyph — because an icon is
 * decoration and must never be the reason a window fails to come up.
 */
@Composable
fun BrandMark(size: Dp, modifier: Modifier = Modifier, shape: Shape = RoundedCornerShape(Radius.Large)) {
    val painter: Painter? = appIcon("pgpony_512")
    Box(modifier.size(size).clip(shape), contentAlignment = Alignment.Center) {
        if (painter != null) {
            androidx.compose.foundation.Image(
                painter = painter,
                contentDescription = null,
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxSize()
            )
        } else {
            Box(Modifier.fillMaxSize().background(Brand.gradient()), contentAlignment = Alignment.Center) {
                Icon(
                    Icons.Filled.Lock,
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(size * 0.5f)
                )
            }
        }
    }
}

/**
 * The primary call to action: a filled button whose fill is the brand gradient.
 *
 * Material3 has no gradient-filled button, and the supported way to get one is exactly this —
 * make the container transparent, drop the content padding to zero, and paint the gradient on a
 * Box inside. Doing it that way rather than with a bare clickable Surface keeps the real
 * `Button`, which means the enabled/disabled semantics, the focus ring and the ripple all behave
 * the way every other button in the app does.
 *
 * Disabled falls back to a flat scheme color: a greyed-out gradient reads as a rendering bug.
 */
@Composable
fun BrandButton(
    onClick: () -> Unit,
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier,
        shape = RoundedCornerShape(Radius.Small),
        contentPadding = PaddingValues(0.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Color.Transparent,
            contentColor = Color.White,
            disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant,
            disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant
        )
    ) {
        Box(
            modifier = Modifier
                .then(if (enabled) Modifier.background(Brand.gradient()) else Modifier)
                .padding(horizontal = Spacing.Large, vertical = Spacing.Medium),
            contentAlignment = Alignment.Center
        ) {
            content()
        }
    }
}

/**
 * A content card: surface color, rounded, with the tonal lift the flat `surface` alone doesn't
 * give in dark mode. Screens adopt this in place of their ad-hoc Surface/Column blocks so that
 * every panel in the app shares one radius and one inset.
 */
@Composable
fun BrandCard(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(Radius.Medium),
        color = MaterialTheme.colorScheme.surfaceVariant,
        tonalElevation = 1.dp
    ) {
        Box(Modifier.padding(Spacing.Large)) { content() }
    }
}

/**
 * A 2dp gradient rule. Used under screen headings, where a plain `Divider` at the same weight
 * reads as a table border rather than as part of the app's identity.
 */
@Composable
fun BrandRule(modifier: Modifier = Modifier) {
    Box(
        modifier
            .fillMaxWidth()
            .height(2.dp)
            .clip(RoundedCornerShape(1.dp))
            .background(Brand.gradient())
    )
}

// ── Screen chrome (D12 batch 2) ────────────────────────────────────────
//
// Before batch 2 every screen opened the same way and none of them opened it identically: a bare
// `Text(headlineSmall)` at a 16dp or 20dp inset, then a hand-picked Spacer, then content. The five
// composables below are that opening — and the section, empty-state and label/value shapes that
// follow it — written once. The point is not to save lines; it is that a user moving between
// Keyring and Settings should not be able to tell that two different days of work built them.
//
// Everything here takes its strings already resolved. None of these is the right place to call
// `tr()`: a screen may want a plural, a formatted argument, or a value that is a path rather than
// copy, and resolving at the call site keeps that decision where the context is.

/**
 * A screen masthead: title, an optional line of orientation under it, an action group pinned to
 * the right, and the gradient rule that closes the band off from the content.
 *
 * [actions] is measured inside a [WrapRow], so a screen with five buttons behaves in German the
 * way the keyring header already does — the group takes a second line rather than crushing its
 * last member. The weighted spacer stays on the outer `Row` because `weight` is a `RowScope`
 * modifier and `WrapRow`'s content lambda has no scope; when the buttons fit, the spacer pushes
 * them to the right edge, and when they don't, the WrapRow claims the remaining width and the
 * spacer collapses to nothing.
 */
@Composable
fun ScreenHeader(
    title: String,
    subtitle: String? = null,
    modifier: Modifier = Modifier,
    actions: @Composable () -> Unit = {}
) {
    Column(modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.padding(end = Spacing.Medium)) {
                Text(
                    title,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                if (subtitle != null) {
                    Spacer(Modifier.height(Spacing.Tight))
                    Text(
                        subtitle,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Spacer(Modifier.weight(1f))
            WrapRow(horizontalAlignment = Alignment.End) { actions() }
        }
        Spacer(Modifier.height(Spacing.Medium))
        BrandRule()
    }
}

/**
 * A heading inside a screen, marked with a short gradient tick rather than a rule.
 *
 * The tick is what makes a section header read as a section header at a glance instead of as one
 * more bold line in a scroll of bold lines — Settings stacks seven of these, and before D12 the
 * only thing separating them from the body copy was a type ramp step.
 */
@Composable
fun SectionHeader(title: String, subtitle: String? = null, modifier: Modifier = Modifier) {
    Column(modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(width = 3.dp, height = 18.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(Brand.gradientVertical())
            )
            Spacer(Modifier.width(Spacing.Small))
            Text(
                title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
        if (subtitle != null) {
            Spacer(Modifier.height(Spacing.Tight))
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 3.dp + Spacing.Small)
            )
        }
    }
}

/**
 * A heading one level below [SectionHeader] — "Proxy", "Keyservers", "Clipboard" inside the
 * Network and Password store cards. No tick: a section has one, and repeating it on the
 * sub-groups inside would flatten the hierarchy the tick exists to express.
 */
@Composable
fun SubHeading(title: String, modifier: Modifier = Modifier) {
    Text(
        title,
        modifier = modifier.padding(bottom = Spacing.Tight),
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.onSurface
    )
}

/**
 * A [SectionHeader] and its controls inside one [BrandCard].
 *
 * Settings is the screen this exists for: seven groups of unrelated controls separated only by a
 * `Spacer(20.dp)`, where a card boundary says what the spacer was trying to.
 */
@Composable
fun SectionCard(
    title: String,
    subtitle: String? = null,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    BrandCard(modifier.fillMaxWidth()) {
        Column {
            SectionHeader(title, subtitle)
            Spacer(Modifier.height(Spacing.Medium))
            content()
        }
    }
}

/**
 * The centred nothing-here state: a washed brand tile carrying an icon, a headline, one sentence
 * of what to do about it, and optionally the control that does it.
 *
 * The message column is width-capped rather than left to fill the window, because an empty state
 * stretched across a maximised 27-inch display is a line of text with no beginning and no end.
 * The cap is in dp rather than characters on purpose: German runs roughly a third longer than
 * English and Japanese runs shorter, and the box should stay the same shape in both.
 *
 * Only [Modifier.fillMaxWidth] is applied here, never `fillMaxSize`. Three of the five screens
 * put their empty state inside a `verticalScroll` column, where the incoming height constraint is
 * unbounded — and Compose's fill modifier falls back to `constraints.minHeight` when the axis is
 * unbounded, which is zero. A `fillMaxSize` baked in would therefore collapse the whole widget to
 * nothing on exactly the screens that scroll. A caller that owns a bounded height and wants the
 * state centred in it passes `Modifier.fillMaxSize()` itself.
 */
@Composable
fun EmptyState(
    icon: ImageVector,
    title: String,
    message: String,
    modifier: Modifier = Modifier,
    action: @Composable () -> Unit = {}
) {
    Box(modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.widthIn(max = 420.dp).padding(Spacing.Section)
        ) {
            Box(
                Modifier
                    .size(72.dp)
                    .clip(RoundedCornerShape(Radius.Large))
                    .background(Brand.gradientWash(0.18f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, contentDescription = null, tint = Brand.Accent, modifier = Modifier.size(34.dp))
            }
            Spacer(Modifier.height(Spacing.Large))
            Text(
                title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(Modifier.height(Spacing.Small))
            Text(
                message,
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(Spacing.Large))
            WrapRow(horizontalAlignment = Alignment.CenterHorizontally) { action() }
        }
    }
}

/**
 * The transient one-line result of the last action — "Public key copied", "Proxy set to …".
 *
 * Before D12 this was a bare `Text` in `colorScheme.primary`, which in the light scheme is purple
 * body copy floating between two controls with nothing to say it is a different kind of thing. A
 * washed strip gives it an edge to sit against without turning a routine confirmation into an
 * alert box.
 *
 * [error] swaps the brand wash for a wash of the scheme's error colour. The card and crypto
 * screens both report success and failure through the same one-line channel, and before D12 the
 * only difference between "Paired" and a PC/SC stack trace was the colour of the type.
 */
@Composable
fun StatusStrip(text: String, modifier: Modifier = Modifier, error: Boolean = false) {
    val wash: Modifier =
        if (error) Modifier.background(MaterialTheme.colorScheme.error.copy(alpha = 0.12f))
        else Modifier.background(Brand.gradientWash(0.16f))
    Box(
        modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(Radius.Small))
            .then(wash)
            .padding(horizontal = Spacing.Medium, vertical = Spacing.Small)
    ) {
        Text(
            text,
            style = MaterialTheme.typography.bodySmall,
            color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
        )
    }
}

/** How a [BrandBadge] is coloured. Carries no copy, so it is safe as an enum. */
enum class BadgeTone { Neutral, Brand, Error }

/**
 * A small status pill — algorithm name, SECRET, EXPIRED, REVOKED.
 *
 * [BadgeTone.Brand] paints the gradient rather than the flat `primary` the old per-screen `Pill`
 * used, which is the one place in a list row where the brand can appear without competing with
 * the row's own content.
 */
@Composable
fun BrandBadge(text: String, tone: BadgeTone = BadgeTone.Neutral, modifier: Modifier = Modifier) {
    val shape = RoundedCornerShape(Radius.Small)
    val fill: Modifier = when (tone) {
        BadgeTone.Neutral -> Modifier.background(MaterialTheme.colorScheme.surfaceVariant)
        BadgeTone.Brand -> Modifier.background(Brand.gradient())
        BadgeTone.Error -> Modifier.background(MaterialTheme.colorScheme.error)
    }
    val ink: Color = when (tone) {
        BadgeTone.Neutral -> MaterialTheme.colorScheme.onSurfaceVariant
        BadgeTone.Brand -> Color.White
        BadgeTone.Error -> MaterialTheme.colorScheme.onPrimary
    }
    Box(modifier.clip(shape).then(fill)) {
        Text(
            text,
            modifier = Modifier.padding(horizontal = Spacing.Small, vertical = 3.dp),
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Medium,
            color = ink
        )
    }
}

// ── Dialog chrome (D12 batch 3) ────────────────────────────────────────

/**
 * Every modal in the app, wearing the same clothes.
 *
 * Before batch 3 there were twelve bare `AlertDialog` call sites and they agreed on nothing: the
 * title was `Text(tr(…))` with whatever `titleLarge` happened to look like, the corner radius was
 * Material's `extraLarge` while every panel behind it had moved to [Radius.Medium], and the two
 * destructive dialogs — factory reset and card keygen — announced themselves only by colouring a
 * word of body copy red. This wrapper is a thin one: it still IS a Material3 `AlertDialog`, so the
 * scrim, the focus handling, the escape-to-dismiss and the platform's window management are
 * untouched. Only the chrome is ours.
 *
 * [destructive] swaps the gradient tick and the title colour for the scheme's error colour. That
 * is the whole treatment on purpose — a dialog that erases a hardware key should be recognisable
 * before it is read, but it should not be so loud that the two ordinary confirmations next to it
 * stop being read at all.
 *
 * The tick matches [SectionHeader]'s, one type size up, so a modal reads as a continuation of the
 * screen that opened it rather than as a different application's window.
 */
@Composable
fun BrandDialog(
    onDismissRequest: () -> Unit,
    title: String,
    confirmButton: @Composable () -> Unit,
    modifier: Modifier = Modifier,
    dismissButton: (@Composable () -> Unit)? = null,
    destructive: Boolean = false,
    content: @Composable () -> Unit
) {
    val error = MaterialTheme.colorScheme.error
    AlertDialog(
        onDismissRequest = onDismissRequest,
        modifier = modifier,
        shape = RoundedCornerShape(Radius.Medium),
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(width = 3.dp, height = 22.dp)
                        .clip(RoundedCornerShape(2.dp))
                        .then(
                            if (destructive) Modifier.background(error)
                            else Modifier.background(Brand.gradientVertical())
                        )
                )
                Spacer(Modifier.width(Spacing.Small))
                Text(
                    title,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = if (destructive) error else MaterialTheme.colorScheme.onSurface
                )
            }
        },
        text = { content() },
        confirmButton = confirmButton,
        dismissButton = dismissButton
    )
}

/**
 * A label and the value it names — "Data folder", then the path.
 *
 * A [WrapRow] rather than a `Row` because the value is very often a filesystem path or a runtime
 * string, neither of which shortens when the label in front of it grows by a third in German.
 * On a narrow window the value drops to its own line instead of the path being clipped.
 */
@Composable
fun LabeledValue(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    monospace: Boolean = false,
    trailing: @Composable () -> Unit = {}
) {
    WrapRow(modifier = modifier, horizontalSpacing = Spacing.Small) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = if (monospace) FontFamily.Monospace else null,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        trailing()
    }
}
