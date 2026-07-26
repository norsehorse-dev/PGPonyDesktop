// QrCode.kt
// PGPony Desktop — D9: QR encode/decode over ZXing (the same library Android uses, so the wire
// format is identical). Encoding a public key can exceed QR capacity — a full RSA-4096
// certificate is a few KB and won't fit even at version-40 — so [encodeToPng] returns null on
// WriterException and the caller shows the 4.1.0 §11 "too large for a QR, share the .asc"
// message instead of a broken image. Decoding reads a QR out of any image file the user picks
// (screenshot, photo export); there is no camera in 1.0.

package com.pgpony.desktop

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.client.j2se.BufferedImageLuminanceSource
import com.google.zxing.client.j2se.MatrixToImageWriter
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.io.File
import javax.imageio.ImageIO

object QrCode {

    /**
     * Encode [text] as a QR and return PNG bytes, or null when the content is too large to fit
     * a QR at any version (ZXing throws WriterException) — the caller then falls back to
     * sharing the armored file.
     *
     * ## Error correction stays at L — and here is why it was nearly changed (D12 Fix4)
     *
     * D9 chose L to maximize capacity, and that choice is correct. It was briefly changed to M
     * while chasing the intermittent QrCodeTest failure, on the evidence of a single certificate
     * that failed at L and decoded at M. Measured properly over 40 freshly generated Ed25519
     * certificates, the level turns out to be irrelevant:
     *
     *      level   general detector fails      PURE_BARCODE fails
     *      L       2 / 40                      0 / 40
     *      M       4 / 40                      0 / 40
     *      Q       2 / 40                      0 / 40
     *
     * M was no better than L; in that sample it was worse. The failing symbols are VALID — the
     * same images decode every time under DecodeHintType.PURE_BARCODE — so nothing is wrong with
     * what this function produces. What varies is whether ZXing's photo-oriented detector can
     * LOCATE a symbol in a pixel-perfect synthetic render, which is a property of the decoder,
     * not of the encoding. The fix therefore lives in [decodeFromImage].
     *
     * Also measured and ruled out along the way: render size (640, 1024, 1280, 2048 behave
     * identically), the quiet zone (a spec-conformant 4-module margin fails on the same keys as
     * a 1-module one), and the binarizer (Hybrid and GlobalHistogram fail together).
     */
    fun encodeToPng(text: String, size: Int = 640): ByteArray? = try {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
        ByteArrayOutputStream().use { out ->
            MatrixToImageWriter.writeToStream(matrix, "PNG", out)
            out.toByteArray()
        }
    } catch (_: Exception) {
        null
    }

    /**
     * Decode the first QR found in [file] (any ImageIO-readable format), or null.
     *
     * ## Two passes (D12 Fix4)
     *
     * ZXing's default detector is built for photographs: it hunts for the finder patterns in an
     * image that may be blurred, rotated, skewed or unevenly lit. On a pixel-perfect synthetic
     * render it intermittently fails to find a symbol that is demonstrably there — a few keys in
     * every forty, deterministically for a given key, at every error-correction level and every
     * render size. `PURE_BARCODE` is the reader for exactly that case: it skips the search and
     * reads the module grid directly, on the assumption that the image is nothing but a barcode.
     * Over the same 40-certificate sample it did not fail once, at any level.
     *
     * So: the photo detector first, because this function's other documented input is a photo of
     * someone else's screen, and that is the case `PURE_BARCODE` cannot handle. Then the grid
     * reader, which covers the screenshots and exported images that make up the common path.
     * Falling back cannot produce a wrong answer — a QR carries its own error-correction
     * codewords, so a misread fails the checksum and throws rather than returning bad key
     * material.
     */
    fun decodeFromImage(file: File): String? {
        val image = try {
            ImageIO.read(file)
        } catch (_: Exception) {
            null
        } ?: return null
        return decodeWith(image, pure = false) ?: decodeWith(image, pure = true)
    }

    /** One decode attempt. [pure] swaps the photo detector for the direct grid reader. */
    private fun decodeWith(image: BufferedImage, pure: Boolean): String? = try {
        val bitmap = BinaryBitmap(HybridBinarizer(BufferedImageLuminanceSource(image)))
        val hints = buildMap<DecodeHintType, Any> {
            put(DecodeHintType.TRY_HARDER, true)
            put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
            if (pure) put(DecodeHintType.PURE_BARCODE, true)
        }
        MultiFormatReader().decode(bitmap, hints).text
    } catch (_: Exception) {
        null
    }
}
