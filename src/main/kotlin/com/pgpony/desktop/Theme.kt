// Theme.kt
// PGPony Desktop — port of ui/theme/AppTheme.kt (Android, Phase A12).
//
// The two ColorSchemes are lifted VERBATIM from the Android file so the desktop app renders the
// exact PGPony palette (purple identity, deep neutral darks, WCAG-checked light scheme). The
// Android file's only platform coupling was SharedPreferences bootstrap; here ThemeState persists
// through java.util.prefs under the same "selected_theme" key name.

package com.pgpony.desktop

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.graphics.Color
import java.util.prefs.Preferences

// D11 — the radio labels are resource keys, not literals. These three sentences already exist in
// the vendored Android translations, so the desktop reuses Android's keys and inherits all five
// languages rather than declaring three desktop-owned strings that say the same thing.
enum class AppTheme(val labelKey: String, val storageKey: String) {
    System("settings_appearance_theme_system", "system"),
    Light("settings_appearance_theme_light", "light"),
    Dark("settings_appearance_theme_dark", "dark");

    companion object {
        /** Inverse of [storageKey]. Unknown values fall through to [System]. */
        fun fromStorage(value: String?): AppTheme = when (value) {
            Light.storageKey -> Light
            Dark.storageKey -> Dark
            else -> System
        }
    }
}

object ThemeState {
    private val prefs: Preferences = Preferences.userRoot().node("app/pgpony/desktop")

    /** Live theme value — read by PGPonyTheme (snapshot subscription), written by Settings. */
    val current: MutableState<AppTheme> =
        mutableStateOf(AppTheme.fromStorage(prefs.get("selected_theme", null)))

    fun set(theme: AppTheme) {
        current.value = theme
        prefs.put("selected_theme", theme.storageKey)
    }
}

/** Resolves the scheme for [theme] right now; System follows the OS setting reactively. */
@Composable
fun resolveColorScheme(theme: AppTheme): ColorScheme {
    val isDark = when (theme) {
        AppTheme.System -> isSystemInDarkTheme()
        AppTheme.Light -> false
        AppTheme.Dark -> true
    }
    return if (isDark) PGPonyDarkColorScheme else PGPonyLightColorScheme
}

@Composable
fun PGPonyTheme(content: @Composable () -> Unit) {
    val theme by ThemeState.current
    MaterialTheme(colorScheme = resolveColorScheme(theme), content = content)
}

// ── Dark scheme — verbatim from Android AppTheme.kt ────────────────────

val PGPonyDarkColorScheme: ColorScheme = darkColorScheme(
    primary = Color(0xFF8B5CF6),
    secondary = Color(0xFF6366F1),
    tertiary = Color(0xFFA78BFA),
    background = Color(0xFF0F0F0F),
    surface = Color(0xFF1A1A1A),
    surfaceVariant = Color(0xFF252525),
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = Color.White,
    onSurface = Color.White,
    onSurfaceVariant = Color(0xFFB0B0B0),
    error = Color(0xFFEF4444)
)

// ── Light scheme — verbatim from Android AppTheme.kt ───────────────────

val PGPonyLightColorScheme: ColorScheme = lightColorScheme(
    primary = Color(0xFF7C3AED),
    secondary = Color(0xFF4F46E5),
    tertiary = Color(0xFF8B5CF6),
    background = Color(0xFFFAFAFA),
    surface = Color.White,
    surfaceVariant = Color(0xFFF1F1F4),
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = Color(0xFF1A1A1A),
    onSurface = Color(0xFF1A1A1A),
    onSurfaceVariant = Color(0xFF505050),
    error = Color(0xFFDC2626)
)
