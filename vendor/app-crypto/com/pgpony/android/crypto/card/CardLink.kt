// CardLink.kt
// PGPony Android — USB Phase 2
//
// Which way we can reach a hardware key right now, and what to tell the user
// when the answer is "not the way you are trying".
//
// WHAT THIS REPLACES. Five card screens each did:
//
//     val nfcAvailable = remember { activity?.isNfcAvailable() == true }
//     val nfcEnabled   = remember { activity?.isNfcEnabled() == true }
//
// Two booleans, one transport, and the assumption that NFC is the only way in
// baked into every screen. With a wired reader that becomes a question with
// two independent answers, and "can I use a card at all" stops being
// answerable by either boolean alone.
//
// Pure Kotlin, no Android imports. The platform reads the four inputs; this
// decides what they mean. That split is why the preference order and the
// advice copy are testable rather than only observable by plugging things in.

package com.pgpony.android.crypto.card

/** How a card is physically reached. */
enum class CardLinkKind { NFC, USB }

/**
 * What to do or say, given what is available. Exhaustive on purpose: the UI
 * should never have to invent a message for a combination nobody considered.
 */
sealed interface CardLinkAdvice {

    /** A reader is attached and usable. Prefer it over asking for a tap. */
    data object UseAttachedReader : CardLinkAdvice

    /** A reader is attached but PGPony has not been granted access to it. */
    data object AttachedReaderNeedsPermission : CardLinkAdvice

    /** NFC is ready and nothing is plugged in. The ordinary case. */
    data object TapNow : CardLinkAdvice

    /**
     * NFC is ready, nothing is plugged in, and this device could also take a
     * wired key.
     *
     * This exists for the case that motivated USB support in the first place:
     * a USB-only key (a 5C Nano) held against the phone will never respond,
     * and the user has no way to know that from a screen that only says "hold
     * your key to the phone". Say what to check instead of timing out
     * silently.
     */
    data object TapNowOrPlugIn : CardLinkAdvice

    /** NFC hardware exists but is switched off, and nothing is plugged in. */
    data object EnableNfc : CardLinkAdvice

    /**
     * No NFC hardware and nothing attached, but the device can take a wired
     * reader. A tablet, or a phone without an NFC radio.
     */
    data object PlugInAReader : CardLinkAdvice

    /** Nothing is possible on this device. */
    data object NoTransportAvailable : CardLinkAdvice
}

/**
 * A snapshot of card connectivity. Cheap to build and safe to recompute, so
 * callers should re-read it on resume and on USB attach/detach rather than
 * caching it for the life of a screen — which is exactly what the `remember`
 * blocks it replaces got wrong the moment a transport could appear mid-session.
 */
data class CardLinkAvailability(
    /** Device has an NFC radio. */
    val nfcPresent: Boolean = false,
    /** NFC radio is present AND switched on. */
    val nfcEnabled: Boolean = false,
    /** Device supports USB host mode at all. */
    val usbSupported: Boolean = false,
    /** A CCID reader is plugged in right now. */
    val usbReaderAttached: Boolean = false,
    /** The user has granted PGPony access to that reader. */
    val usbPermissionGranted: Boolean = false,
) {

    /** USB is usable only when a reader is attached AND permitted. */
    val usbUsable: Boolean
        get() = usbSupported && usbReaderAttached && usbPermissionGranted

    val nfcUsable: Boolean
        get() = nfcPresent && nfcEnabled

    val usable: Set<CardLinkKind>
        get() = buildSet {
            if (usbUsable) add(CardLinkKind.USB)
            if (nfcUsable) add(CardLinkKind.NFC)
        }

    val anyUsable: Boolean get() = usable.isNotEmpty()

    /**
     * Which link to try without asking.
     *
     * **USB wins when it is usable**, even with NFC on. A key already plugged
     * in is a clearer statement of intent than a radio that happens to be
     * enabled, and asking someone to tap a key they are already holding
     * against a cable is the kind of thing that makes a feature feel broken.
     *
     * Null when neither is usable; the UI should show [advice] instead of a
     * prompt.
     */
    val preferred: CardLinkKind?
        get() = when {
            usbUsable -> CardLinkKind.USB
            nfcUsable -> CardLinkKind.NFC
            else -> null
        }

    /**
     * True when the user genuinely has a choice worth offering. A manual
     * override only makes sense with more than one usable link; offering a
     * picker with one entry is noise.
     */
    val offerChoice: Boolean get() = usable.size > 1

    /** What the screen should say or do. See [CardLinkAdvice]. */
    val advice: CardLinkAdvice
        get() = when {
            usbUsable -> CardLinkAdvice.UseAttachedReader

            // Attached but not permitted outranks a tap prompt: the user has
            // physically plugged something in, so the next step they expect is
            // about that, not about NFC.
            usbSupported && usbReaderAttached -> CardLinkAdvice.AttachedReaderNeedsPermission

            nfcUsable && usbSupported -> CardLinkAdvice.TapNowOrPlugIn
            nfcUsable -> CardLinkAdvice.TapNow

            nfcPresent && !nfcEnabled -> CardLinkAdvice.EnableNfc

            usbSupported -> CardLinkAdvice.PlugInAReader

            else -> CardLinkAdvice.NoTransportAvailable
        }

    companion object {
        /** Nothing works. The value a null activity should collapse to. */
        val NONE = CardLinkAvailability()
    }
}
