// KeyringSectionsTest.kt
// PGPony Desktop 3.0.5: the key list split into My Keys and Public Keys (KeyringSections.kt), a
// tester's request. The section rule is PGPony Android's PGPKeyEntity.section() without Contacts:
// a key pair or a card-backed key is the user's own, anything else is a public key.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.PGPKeyEntity
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class KeyringSectionsTest {

    @BeforeTest
    fun hookPrefs() {
        KeyringSectionPrefs.prefsOverride = MemoryPreferences()
    }

    @AfterTest
    fun unhookPrefs() {
        KeyringSectionPrefs.prefsOverride = null
    }

    private fun key(
        fp: String,
        name: String = "Key $fp",
        isKeyPair: Boolean = false,
        isCardBacked: Boolean = false,
        algorithm: KeyAlgorithm = KeyAlgorithm.ED25519_CV25519,
        createdAt: Long = 0L
    ) = PGPKeyEntity(
        id = fp, fingerprint = fp, userID = "$name <${name.lowercase().replace(' ', '.')}@example.invalid>",
        userName = name, userEmail = "${name.lowercase().replace(' ', '.')}@example.invalid",
        algorithm = algorithm, isKeyPair = isKeyPair, createdAt = createdAt,
        isCardBacked = isCardBacked, cardSerial = if (isCardBacked) "0011AABB" else null
    )

    @Test
    fun aKeyPairIsMine() {
        assertEquals(KeySection.MINE, key("AA01", isKeyPair = true).keySection())
    }

    @Test
    fun aCardBackedKeyIsMineEvenWithoutASecretHere() {
        // A card imported on its own: the secret is on the card, so isKeyPair is false.
        assertEquals(KeySection.MINE, key("AA02", isCardBacked = true).keySection())
        // A key moved to a card while its stub stays in the keyring.
        assertEquals(KeySection.MINE, key("AA03", isKeyPair = true, isCardBacked = true).keySection())
    }

    @Test
    fun aPublicOnlyKeyIsPublic() {
        assertEquals(KeySection.PUBLIC, key("AA04").keySection())
    }

    @Test
    fun splitPutsEveryKeyInExactlyOneSectionAndAlwaysListsBoth() {
        val keys = listOf(key("01", isKeyPair = true), key("02"), key("03", isCardBacked = true), key("04"))
        val split = KeyringSections.split(keys, "", SortMode.RECENT)
        assertEquals(KeySection.entries.toSet(), split.keys)
        assertEquals(listOf("01", "03"), split.getValue(KeySection.MINE).map { it.fingerprint })
        assertEquals(listOf("02", "04"), split.getValue(KeySection.PUBLIC).map { it.fingerprint })

        val onlyPublic = KeyringSections.split(listOf(key("05")), "", SortMode.RECENT)
        assertTrue(onlyPublic.getValue(KeySection.MINE).isEmpty(), "an empty section is still in the map")
    }

    @Test
    fun searchCoversBothSections() {
        val keys = listOf(
            key("A1", name = "Alice Work", isKeyPair = true),
            key("B1", name = "Bob"),
            key("A2", name = "Alice Home"),
            key("C1", name = "Carol", isCardBacked = true)
        )
        val split = KeyringSections.split(keys, "alice", SortMode.RECENT)
        assertEquals(listOf("A1"), split.getValue(KeySection.MINE).map { it.fingerprint })
        assertEquals(listOf("A2"), split.getValue(KeySection.PUBLIC).map { it.fingerprint })

        // A grouped fingerprint still matches, in whichever section the key sits.
        val byFp = KeyringSections.split(listOf(key("ABCD1234", isCardBacked = true)), "abcd 1234", SortMode.RECENT)
        assertEquals(1, byFp.getValue(KeySection.MINE).size)
    }

    @Test
    fun sortingAppliesWithinEachSection() {
        val keys = listOf(
            key("M1", name = "Zed", isKeyPair = true),
            key("P1", name = "Yan"),
            key("M2", name = "Abe", isCardBacked = true),
            key("P2", name = "Bea")
        )
        val byName = KeyringSections.split(keys, "", SortMode.NAME)
        assertEquals(listOf("M2", "M1"), byName.getValue(KeySection.MINE).map { it.fingerprint })
        assertEquals(listOf("P2", "P1"), byName.getValue(KeySection.PUBLIC).map { it.fingerprint })

        // Recent keeps the DAO order (createdAt DESC) inside each section.
        val recent = KeyringSections.split(keys, "", SortMode.RECENT)
        assertEquals(listOf("M1", "M2"), recent.getValue(KeySection.MINE).map { it.fingerprint })
        assertEquals(listOf("P1", "P2"), recent.getValue(KeySection.PUBLIC).map { it.fingerprint })
    }

    @Test
    fun collapsedStateIsRememberedPerSection() {
        assertTrue(KeyringSectionPrefs.collapsed().isEmpty())
        assertEquals(setOf(KeySection.MINE), KeyringSectionPrefs.toggle(KeySection.MINE))
        assertEquals(setOf(KeySection.MINE), KeyringSectionPrefs.collapsed(), "read back from prefs")
        KeyringSectionPrefs.toggle(KeySection.PUBLIC)
        assertEquals(setOf(KeySection.MINE, KeySection.PUBLIC), KeyringSectionPrefs.collapsed())
        KeyringSectionPrefs.toggle(KeySection.MINE)
        assertEquals(setOf(KeySection.PUBLIC), KeyringSectionPrefs.collapsed())
    }

    @Test
    fun aSearchKeepsEverySectionExpanded() {
        val collapsed = setOf(KeySection.MINE)
        assertTrue(KeyringSectionPrefs.isCollapsed(KeySection.MINE, collapsed, ""))
        assertFalse(KeyringSectionPrefs.isCollapsed(KeySection.MINE, collapsed, "alice"))
        assertFalse(KeyringSectionPrefs.isCollapsed(KeySection.PUBLIC, collapsed, ""))
    }

    @Test
    fun everySectionStringResolvesInEveryLanguage() {
        val i18nPrefs = MemoryPreferences()
        I18n.prefsOverride = i18nPrefs
        try {
            for (lang in I18n.SUPPORTED) {
                I18n.selectLanguage(lang)
                for (section in KeySection.entries) {
                    for (k in listOf(section.titleKey, section.emptyKey)) {
                        assertTrue(tr(k) != k, "$lang: $k resolves")
                    }
                }
                assertTrue(tr("d_keyring_section_no_matches") != "d_keyring_section_no_matches", "$lang: no_matches")
            }
            I18n.selectLanguage("en")
            assertEquals("My Keys", tr("keyring_section_my_keys"))
            assertEquals("Public Keys", tr("keyring_section_public_keys"))
        } finally {
            I18n.selectLanguage(I18n.SYSTEM)
            I18n.prefsOverride = null
        }
    }
}
