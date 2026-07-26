// AndroidAppShim.kt
// PGPony Desktop — D2a vendor shim.
//
// The vendored schema file (data/PGPKeyEntity.kt) has one Android reach-through:
// TrustLevel.localizedName()/localizedDescription() resolve strings via
// `com.pgpony.android.PGPonyApp.instance.getString(com.pgpony.android.R.string.*)` — fully
// qualified inline, so the file compiles only if those two symbols exist. This shim supplies
// them on the desktop classpath with the English values from Android's res/values/strings.xml.
//
// D11b — these eight strings are DEAD on the desktop and are deliberately NOT localized.
// Nothing under src/ calls TrustLevel.localizedName() or localizedDescription(); the UI
// resolves trust names through trustName() in KeyDetailDialog.kt, which maps the enum to a
// key at the UI boundary and leaves the persisted backup wire value alone. This shim exists
// only so the vendored data/PGPKeyEntity.kt compiles. Translating unreachable code would
// just mint six locales' worth of strings no one can ever see.
//
// STILL SUPERSEDABLE by the upstream cleanup candidate recorded in PHASE_D2_NOTES.md —
// moving the localized helpers off the enum into a UI-layer extension in PGPonyAndroid,
// after which the entity file carries no app/R references and this shim is deleted outright.

package com.pgpony.android

/** Desktop stand-in for the Android Application singleton — string lookup only. */
object PGPonyApp {
    val instance: PGPonyApp get() = this

    fun getString(resId: Int): String = when (resId) {
        R.string.trust_level_unknown_name -> "Unknown"
        R.string.trust_level_unverified_name -> "Unverified"
        R.string.trust_level_verified_name -> "Verified"
        R.string.trust_level_ultimate_name -> "Ultimate"
        R.string.trust_level_unknown_description -> "No validation performed"
        R.string.trust_level_unverified_description -> "Added but not vetted — proceed with caution"
        R.string.trust_level_verified_description -> "Fingerprint compared via a trusted channel"
        R.string.trust_level_ultimate_description -> "Your own key, or one you fully control"
        else -> ""
    }
}

/** Desktop stand-in for the generated Android R class — only the ids the vendored code uses. */
object R {
    object string {
        const val trust_level_unknown_name = 1001
        const val trust_level_unverified_name = 1002
        const val trust_level_verified_name = 1003
        const val trust_level_ultimate_name = 1004
        const val trust_level_unknown_description = 1005
        const val trust_level_unverified_description = 1006
        const val trust_level_verified_description = 1007
        const val trust_level_ultimate_description = 1008
    }
}
