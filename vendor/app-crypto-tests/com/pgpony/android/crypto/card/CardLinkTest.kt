// CardLinkTest.kt
// PGPony Android — USB Phase 2
//
// The transport-availability decisions, tested without hardware.
//
// These are cheap to write and the alternative is discovering the preference
// order by plugging things in, which is slow and only covers the combinations
// that happen to occur on one desk. There are 2^5 input combinations here;
// most are unreachable in practice, and the ones that matter are the ones
// where two transports disagree.

package com.pgpony.android.crypto.card

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CardLinkTest {

    private fun link(
        nfcPresent: Boolean = false,
        nfcEnabled: Boolean = false,
        usbSupported: Boolean = false,
        usbReaderAttached: Boolean = false,
        usbPermissionGranted: Boolean = false,
    ) = CardLinkAvailability(
        nfcPresent, nfcEnabled, usbSupported, usbReaderAttached, usbPermissionGranted
    )

    private val nfcOnly = link(nfcPresent = true, nfcEnabled = true)
    private val usbReady = link(
        usbSupported = true, usbReaderAttached = true, usbPermissionGranted = true
    )
    private val both = link(
        nfcPresent = true, nfcEnabled = true,
        usbSupported = true, usbReaderAttached = true, usbPermissionGranted = true,
    )

    // ── preference ───────────────────────────────────────────────────────

    /**
     * THE preference decision. A key already plugged in is a clearer statement
     * of intent than a radio that happens to be on, and asking someone to tap
     * a key they are holding against a cable makes the feature feel broken.
     */
    @Test
    fun attachedReaderWinsOverEnabledNfc() {
        assertEquals(CardLinkKind.USB, both.preferred)
        assertEquals(CardLinkAdvice.UseAttachedReader, both.advice)
    }

    @Test
    fun nfcAloneIsPreferredWhenNothingIsPluggedIn() {
        assertEquals(CardLinkKind.NFC, nfcOnly.preferred)
    }

    @Test
    fun usbAloneIsPreferredOnADeviceWithNoNfc() {
        assertEquals(CardLinkKind.USB, usbReady.preferred)
    }

    @Test
    fun nothingUsable_hasNoPreference() {
        assertNull(link().preferred)
        assertNull(link(nfcPresent = true).preferred)
        assertNull(link(usbSupported = true).preferred)
    }

    // ── usability, and the ways USB is not usable ────────────────────────

    /**
     * A reader that is attached but not permitted is NOT usable. Treating it
     * as usable would send the operation down the USB path and fail at
     * openDevice, which returns null and would surface as a confusing
     * "no card" rather than a permission prompt.
     */
    @Test
    fun attachedButUnpermittedReaderIsNotUsable() {
        val l = link(usbSupported = true, usbReaderAttached = true)
        assertFalse(l.usbUsable)
        assertFalse(l.anyUsable)
        assertEquals(CardLinkAdvice.AttachedReaderNeedsPermission, l.advice)
    }

    @Test
    fun permissionWithoutAnAttachedReaderIsNotUsable() {
        val l = link(usbSupported = true, usbPermissionGranted = true)
        assertFalse(l.usbUsable)
    }

    @Test
    fun readerAttachedOnADeviceWithoutUsbHostIsNotUsable() {
        val l = link(usbReaderAttached = true, usbPermissionGranted = true)
        assertFalse("usbSupported gates everything else", l.usbUsable)
    }

    @Test
    fun nfcPresentButOffIsNotUsable() {
        val l = link(nfcPresent = true, nfcEnabled = false)
        assertFalse(l.nfcUsable)
        assertEquals(CardLinkAdvice.EnableNfc, l.advice)
    }

    // ── advice, including the one the whole feature exists for ───────────

    /**
     * The case that motivated USB support. A USB-only key held against the
     * phone will never respond, and a screen that only says "hold your key to
     * the phone" gives the user no way to work that out. On a device that
     * could take a wired key, say both.
     */
    @Test
    fun nfcReadyOnAUsbCapableDevice_mentionsBothOptions() {
        val l = link(nfcPresent = true, nfcEnabled = true, usbSupported = true)
        assertEquals(CardLinkAdvice.TapNowOrPlugIn, l.advice)
    }

    @Test
    fun nfcReadyOnADeviceThatCannotTakeAReader_saysOnlyTap() {
        assertEquals(CardLinkAdvice.TapNow, nfcOnly.advice)
    }

    /**
     * An attached-but-unpermitted reader outranks a tap prompt even with NFC
     * on. The user physically plugged something in, so the next step they
     * expect is about that.
     */
    @Test
    fun unpermittedReaderOutranksATapPrompt() {
        val l = link(
            nfcPresent = true, nfcEnabled = true,
            usbSupported = true, usbReaderAttached = true,
        )
        assertEquals(CardLinkAdvice.AttachedReaderNeedsPermission, l.advice)
    }

    @Test
    fun noNfcHardwareButUsbCapable_asksForAReader() {
        assertEquals(CardLinkAdvice.PlugInAReader, link(usbSupported = true).advice)
    }

    @Test
    fun nothingAtAll_saysSo() {
        assertEquals(CardLinkAdvice.NoTransportAvailable, link().advice)
        assertEquals(CardLinkAdvice.NoTransportAvailable, CardLinkAvailability.NONE.advice)
    }

    // ── offering a choice ────────────────────────────────────────────────

    @Test
    fun aChoiceIsOfferedOnlyWhenThereIsOne() {
        assertTrue("two usable links is a real choice", both.offerChoice)
        assertFalse("one link is not a choice", nfcOnly.offerChoice)
        assertFalse(usbReady.offerChoice)
        assertFalse(link().offerChoice)
    }

    @Test
    fun usableSetReflectsBothTransports() {
        assertEquals(setOf(CardLinkKind.USB, CardLinkKind.NFC), both.usable)
        assertEquals(setOf(CardLinkKind.NFC), nfcOnly.usable)
        assertEquals(setOf(CardLinkKind.USB), usbReady.usable)
        assertEquals(emptySet<CardLinkKind>(), link().usable)
    }

    /**
     * Every input combination must produce coherent advice.
     *
     * The rule is NOT "a usable link implies a go-ahead message". An earlier
     * version of this test asserted that and failed, correctly, on: NFC on,
     * reader attached, permission not granted. There NFC is usable and the
     * advice is still AttachedReaderNeedsPermission, deliberately, because
     * telling someone to grant access to the key they just plugged in beats
     * telling them to tap instead.
     *
     * The real rule is narrower: **advice must never send the user to find a
     * transport they already have.** EnableNfc, PlugInAReader and
     * NoTransportAvailable all say "you have nothing usable", so none of them
     * may appear while something is usable. AttachedReaderNeedsPermission says
     * "there is a better option one tap away", which is a different claim.
     *
     * UI CONSEQUENCE, and the reason this is worth writing down rather than
     * only asserting: on that combination the screen must still let the user
     * fall back to NFC. If they decline the permission dialog and the only
     * thing on screen is a request to grant it, they are stuck in front of a
     * transport that would have worked.
     */
    @Test
    fun everyCombinationIsCoherent() {
        val meansNothingIsUsable = setOf(
            CardLinkAdvice.EnableNfc,
            CardLinkAdvice.PlugInAReader,
            CardLinkAdvice.NoTransportAvailable,
        )
        for (bits in 0 until 32) {
            val l = link(
                nfcPresent = bits and 1 != 0,
                nfcEnabled = bits and 2 != 0,
                usbSupported = bits and 4 != 0,
                usbReaderAttached = bits and 8 != 0,
                usbPermissionGranted = bits and 16 != 0,
            )
            val advice = l.advice
            if (l.anyUsable) {
                assertFalse(
                    "a link is usable but advice tells the user to go find one: $l -> $advice",
                    advice in meansNothingIsUsable
                )
            } else {
                assertTrue(
                    "nothing is usable but advice implies otherwise: $l -> $advice",
                    advice in meansNothingIsUsable ||
                        advice == CardLinkAdvice.AttachedReaderNeedsPermission
                )
            }
            assertEquals(
                "preferred must agree with usable: $l",
                l.anyUsable, l.preferred != null
            )
        }
    }

    /**
     * Pinned separately from the exhaustive test, because it is the one
     * combination where advice and usability legitimately disagree and it
     * would otherwise look like an oversight to whoever reads this next.
     */
    @Test
    fun nfcUsableWithAnUnpermittedReader_stillAdvisesAboutTheReader() {
        val l = link(
            nfcPresent = true, nfcEnabled = true,
            usbSupported = true, usbReaderAttached = true,
        )
        assertTrue("NFC really is usable here", l.nfcUsable)
        assertEquals(CardLinkKind.NFC, l.preferred)
        assertEquals(CardLinkAdvice.AttachedReaderNeedsPermission, l.advice)
    }
}
