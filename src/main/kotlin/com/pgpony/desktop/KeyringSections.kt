// KeyringSections.kt
// PGPony Desktop 3.0.5: the key list in two sections, My Keys and Public Keys, the way the phone
// apps split it (a tester's request). The rule is PGPony Android's PGPKeyEntity.section() in
// KeyringViewModel.kt without its Contacts section: the desktop has no address book, so a key with
// no secret here and no card behind it is simply someone else's public key.
//
// Kept out of KeyringScreen.kt so the rule, the search and the per-section sort can be tested
// without Compose (KeyringSectionsTest).

package com.pgpony.desktop

import com.pgpony.android.data.PGPKeyEntity
import java.util.prefs.Preferences

/**
 * Which section of the key list a key is drawn in, in display order. [prefName] is the name the
 * collapsed state is stored under, the same names Android uses for the same sections.
 */
enum class KeySection(val prefName: String, val titleKey: String, val emptyKey: String) {
    MINE("MINE", "keyring_section_my_keys", "d_keyring_section_mine_empty"),
    PUBLIC("PUBLIC", "keyring_section_public_keys", "d_keyring_section_public_empty")
}

/**
 * My Keys holds what the user can sign and decrypt with: a key pair, or a key whose secret lives on
 * a hardware key. A card-backed key goes there even when isKeyPair is false for it, which is how a
 * card imported on its own is stored (the private material is on the card, not in the key store).
 */
fun PGPKeyEntity.keySection(): KeySection =
    if (isKeyPair || isCardBacked) KeySection.MINE else KeySection.PUBLIC

object KeyringSections {

    /** Does [key] match the search box? An empty query matches every key. */
    fun matches(key: PGPKeyEntity, query: String): Boolean {
        val q = query.trim()
        if (q.isBlank()) return true
        return key.userID.contains(q, ignoreCase = true) ||
            key.userEmail.contains(q, ignoreCase = true) ||
            key.fingerprint.contains(q.replace(" ", ""), ignoreCase = true)
    }

    /**
     * Filter [keys] by [query], sort by [sortMode] and split them by section. Search covers every
     * section; sorting applies within each one. Every section is in the map, empty or not, so the
     * screen can show a section's own empty line.
     */
    fun split(keys: List<PGPKeyEntity>, query: String, sortMode: SortMode): Map<KeySection, List<PGPKeyEntity>> {
        val filtered = keys.filter { matches(it, query) }
        val sorted = when (sortMode) {
            SortMode.RECENT -> filtered            // DAO order: createdAt DESC
            SortMode.NAME -> filtered.sortedBy { it.userName.lowercase().ifBlank { it.userEmail } }
            SortMode.ALGORITHM -> filtered.sortedBy { it.algorithm.displayName }
        }
        val bySection = sorted.groupBy { it.keySection() }
        return KeySection.entries.associateWith { bySection[it].orEmpty() }
    }
}

/**
 * The collapsed sections, remembered across launches. A user who collapses My Keys can open the
 * app without their own keys on screen. Stored as section names joined by newlines under the same
 * key Android uses.
 */
object KeyringSectionPrefs {
    const val KEY_COLLAPSED = "keyring_collapsed_sections"

    /** Test hook: a scratch node instead of the real one. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences = prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun collapsed(): Set<KeySection> {
        val names = prefs().get(KEY_COLLAPSED, "").split('\n').filter { it.isNotBlank() }.toSet()
        return KeySection.entries.filter { it.prefName in names }.toSet()
    }

    /** Flip [section] between collapsed and expanded and return the new set. */
    fun toggle(section: KeySection): Set<KeySection> {
        val current = collapsed()
        val updated = if (section in current) current - section else current + section
        prefs().put(KEY_COLLAPSED, updated.joinToString("\n") { it.prefName })
        runCatching { prefs().flush() }
        return updated
    }

    /** A section is drawn collapsed only while no search is active, so a match is never hidden. */
    fun isCollapsed(section: KeySection, collapsed: Set<KeySection>, query: String): Boolean =
        section in collapsed && query.isBlank()
}
