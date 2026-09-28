// QrCode.kt
// PGPony Desktop — D9: QR encode/decode over ZXing (the same library Android uses, so the wire
// format is identical). Encoding a public key can exceed QR capacity — a full RSA-4096
// certificate is a few KB and won't fit even at version-40 — so [encodeToPng] returns null on
// WriterException and the caller shows the 4.1.0 §11 "too large for a QR, share the .asc"
// message instead of a broken image. Decoding reads a QR out of any image file the user picks
// (screenshot, photo export); there is no camera in 1.0.
//
// 3.0.0 (stage 4c, Android 4.4.1 audit item 10): a key too large for one symbol is shown as an
// animated sequence of framed symbols (QrChunking), each encoded at its natural module size and
// scaled by a whole number, as Android 4.5.1 does (#63). Import reads every QR in every chosen
// image and reassembles the frames.

package com.pgpony.desktop

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.client.j2se.BufferedImageLuminanceSource
import com.google.zxing.client.j2se.MatrixToImageWriter
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.multi.qrcode.QRCodeMultiReader
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
     * [text] as the PNG symbols to show: one for a key that fits, or the frames of a split key.
     * Null when even [QrChunking.MAX_FRAMES] frames cannot hold it.
     */
    fun encodeFrames(text: String, target: Int = FRAME_TARGET): List<ByteArray>? {
        val parts = QrChunking.split(text) ?: return null
        val pngs = parts.map { encodeSymbolPng(it, target) }
        return if (pngs.any { it == null }) null else pngs.filterNotNull()
    }

    /** Pixels a framed symbol is scaled toward (Android QrBitmap.TARGET). */
    const val FRAME_TARGET = 800

    /**
     * One symbol at its natural module size, scaled by a whole number toward [target] pixels:
     * every frame gets the same crisp modules with no variable border (Android 4.5.1, #63).
     */
    fun encodeSymbolPng(text: String, target: Int = FRAME_TARGET): ByteArray? = try {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 1, 1, hints)
        val modules = matrix.width
        val scale = (target / modules).coerceAtLeast(1)
        val size = modules * scale
        val image = BufferedImage(size, size, BufferedImage.TYPE_BYTE_BINARY)
        val g = image.createGraphics()
        try {
            g.color = java.awt.Color.WHITE
            g.fillRect(0, 0, size, size)
            g.color = java.awt.Color.BLACK
            for (y in 0 until modules) for (x in 0 until modules) {
                if (matrix.get(x, y)) g.fillRect(x * scale, y * scale, scale, scale)
            }
        } finally {
            g.dispose()
        }
        ByteArrayOutputStream().use { out ->
            ImageIO.write(image, "PNG", out)
            out.toByteArray()
        }
    } catch (_: Exception) {
        null
    }

    /**
     * Every QR in [file]: a screenshot may hold several frames at once. The multi reader
     * first, then the single passes of [decodeFromImage] for what it misses.
     */
    fun decodeAllFromImage(file: File): List<String> {
        val image = readImageBounded(file) ?: return emptyList()
        val found = linkedSetOf<String>()
        runCatching {
            val bitmap = BinaryBitmap(HybridBinarizer(BufferedImageLuminanceSource(image)))
            val hints = mapOf(
                DecodeHintType.TRY_HARDER to true,
                DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)
            )
            QRCodeMultiReader().decodeMultiple(bitmap, hints).forEach { found += it.text }
        }
        if (found.isEmpty()) (decodeWith(image, pure = false) ?: decodeWith(image, pure = true))?.let { found += it }
        return found.toList()
    }

    /** What a set of decoded QR texts adds up to. */
    sealed interface Import {
        data class Key(val armored: String) : Import
        data class Partial(val have: Int, val total: Int) : Import
        data object Mixed : Import
        data object NotAKey : Import
        data object Empty : Import
    }

    /**
     * Reassemble [texts] (from one image or several): a complete key, a split key missing
     * frames, frames of two different keys, or no key at all.
     */
    fun importFrom(texts: List<String>): Import {
        if (texts.isEmpty()) return Import.Empty
        texts.firstOrNull { !QrChunking.isFrame(it) && it.contains("-----BEGIN PGP") }?.let { return Import.Key(it) }
        val frames = texts.filter { QrChunking.isFrame(it) }
        if (frames.isEmpty()) return Import.NotAKey
        val collector = QrChunking.Collector()
        var restarted = false
        for (raw in frames.sortedBy { QrChunking.parse(it)?.id.orEmpty() }) {
            when (val o = collector.offer(raw)) {
                is QrChunking.Outcome.Complete ->
                    return if (o.text.contains("-----BEGIN PGP")) Import.Key(o.text) else Import.NotAKey
                is QrChunking.Outcome.Restarted -> restarted = true
                else -> Unit
            }
        }
        return when {
            restarted -> Import.Mixed
            collector.expected == 0 -> Import.NotAKey
            else -> Import.Partial(collector.have, collector.expected)
        }
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
        val image = readImageBounded(file) ?: return null
        return decodeWith(image, pure = false) ?: decodeWith(image, pure = true)
    }

    /** 3.0.0 (4d): the largest image decoded: a phone screenshot is a few megapixels. */
    internal const val MAX_IMAGE_PIXELS = 40L * 1000 * 1000

    /**
     * [file] as an image, or null. The size in the image's header is checked before any pixel is
     * decoded: a small file can declare a huge image, and decoding it would exhaust the heap.
     */
    internal fun readImageBounded(file: File): BufferedImage? {
        return try {
            ImageIO.createImageInputStream(file)?.use { stream ->
                val reader = ImageIO.getImageReaders(stream).asSequence().firstOrNull()
                if (reader == null) {
                    null
                } else {
                    try {
                        reader.setInput(stream, true, true)
                        val w = reader.getWidth(0).toLong()
                        val h = reader.getHeight(0).toLong()
                        if (w <= 0 || h <= 0 || w * h > MAX_IMAGE_PIXELS) null else reader.read(0)
                    } finally {
                        reader.dispose()
                    }
                }
            }
        } catch (_: Exception) {
            null
        }
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
