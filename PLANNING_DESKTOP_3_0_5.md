# PGPony Desktop 3.0.5 Planning

Status: Rev 1, 2026-10-31. Base: 3.0.4.
Release model: patch release, no release candidates; self-tested on the Mac, then the usual release flow.

Size tags: S (an evening), M (a few evenings), L (a week or more of evenings).

## 1. Rules for this cycle

- Same rules as 3.0.x: no hand edits to vendored files, no personal names or handles in this doc, commits or
  release notes (issue numbers, "a user" or "a tester"), no em dashes or en dashes.
- New desktop strings go into every language the desktop ships (`I18n.SUPPORTED`, 11 locales). Wording the
  mobile apps already have is reused through the vendored Android strings, not translated again.

## 2. Key import from Windows-saved armor (#13) (S, done)

GnuPG text exports saved on Windows end their lines in CR CR LF. With an armor header in the block
("Version: GnuPG v1"), BouncyCastle's ArmoredInputStream rejects it as invalid armor; without a header the
same text imports, which is why deleting the header line looked like the fix. A leading UTF-8 BOM made the
text read as nothing.

Fix (DesktopKeyRepository): `normalizeArmor` drops a BOM and turns `\r+\n` and lone `\r` into `\n` before
`importArmoredText`, `importBytes` (armored input only, binary untouched) and `previewArmoredText` parse.
Tests: `windowsSavedArmorWithVersionHeaderImports`, `normalizeArmorLeavesBinaryAndCleanTextAlone`.

## 3. Key list split into My Keys and Public Keys (S, a tester's request)

Today the key list is one flat list; only the avatar tile and the Secret / Card badges tell a key pair from
someone else's key. The phone apps split it into sections, and this brings the desktop in line with PGPony
Android (KeyringViewModel `PGPKeyEntity.section()`, KeyringScreen `keySection()`).

Rule, Android's minus its Contacts section (the desktop has no address book):

| Key | Section |
| --- | --- |
| key pair (`isKeyPair`) | My Keys |
| card-backed (`isCardBacked`, secret on a hardware key) | My Keys |
| anything else | Public Keys |

A card-backed key goes in My Keys even when `isKeyPair` is false, because the user signs and decrypts with it.

Behaviour:

1. One section builder draws both sections: a heading in its own colour (primary for My Keys, tertiary for
   Public Keys, as on Android) with the count, and a chevron that collapses it.
2. The collapsed state is remembered per section (Preferences, `keyring_collapsed_sections`, the same key
   name Android uses). A section stays expanded while a search is active, so a match is never hidden.
3. Search covers both sections. Sorting (Recent, Name, Algorithm) applies within each section. The desktop
   has no manual order (deferred since D2c), so there is none to carry over.
4. Every per-key action stays as it is in both sections: open Key Detail, copy public key, delete (hidden
   by Hide destructive actions), the same-identity badge. The desktop list has no multi-select or context
   menu, so there is nothing else to carry.
5. Empty states. An empty keyring and a search with no match anywhere keep their whole-screen states. When
   only one section is empty, it keeps its heading and shows a line of its own: no key pairs yet, no public
   keys yet, or no matches in this section during a search. Android hides an empty section; the desktop
   keeps the heading because a lone section on a wide window reads as the whole keyring.

Strings: the headings reuse `keyring_section_my_keys` and `keyring_section_public_keys` from the vendored
Android strings, already translated in all 11 languages, so the wording matches the phones. New desktop
strings `d_keyring_section_mine_empty`, `d_keyring_section_public_empty` and `d_keyring_section_no_matches`
go into all 11 `i18n/` locales. The chevron reuses `help_row_collapse_cd` / `help_row_expand_cd`.

Code: `KeySection` and `PGPKeyEntity.keySection()` plus `KeyringSections.split` (search and sort per
section, pure, testable) and `KeyringSectionPrefs` in `KeyringSections.kt`; `KeyringScreen.kt` draws them.

Tests (`KeyringSectionsTest`): key pair, card-backed with and without `isKeyPair`, public only; search across
sections; sort within a section; collapsed state round trip.

## 4. Card icon on card-linked rows (S, done, approved for 3.0.5)

Backlog: "an icon in the key list for card-linked keys". Since 1.1.0 a card-backed row already shows a text
Card badge. What is left is the icon: the avatar tile at the head of the row would show the card icon
(`Icons.Filled.CreditCard`, the one the Cards tab uses) instead of the key icon, filled like a key pair.
About ten lines in `KeyAvatar`, no new strings (the tile stays decorative; the Card badge carries the text).
Approved for 3.0.5 and built: the tile shows the card icon, filled, for any card-backed key.

## 5. Questions for Kevin

- Q1. Section 4: add the card icon to 3.0.5, or leave it in the backlog? Answered: add it to 3.0.5.

## 6. Status of this document

Rev 1: #13 fix (done) and the key list sections.
Rev 2: card icon approved and built (section 4). Goes to done when 3.0.5 ships.
