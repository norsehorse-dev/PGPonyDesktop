// FileCryptoOps.kt
// PGPony Desktop — D3b file operations on the vendored STREAM APIs (encryptStream /
// decryptStream / signDetachedStream / verifyDetachedStream), so large files never fully load
// into memory. Output naming follows gpg conventions: encrypt → <name>.gpg (binary) or .asc
// (armored); detached signature → <name>.sig / .asc; decrypt restores the literal-packet
// filename when present, else strips the known extension. Existing outputs are never
// overwritten — a numbered variant is chosen instead.
//
// D11b — localized. FileOutcome.detail is shown verbatim in the results list, so every detail
// string is a key. The signature note carries its own leading separator. Internal names
// (body.txt, the temp-file prefixes, the armor headers) are protocol, not copy.

package com.pgpony.desktop

import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.crypto.mime.MimeParser
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import kotlin.io.path.extension
import kotlin.io.path.name
import kotlin.io.path.nameWithoutExtension

class FileCryptoOps(
    private val repo: DesktopKeyRepository,
    private val crypto: PGPCryptoService = PGPCryptoService.shared
) {

    data class FileOutcome(
        val input: Path,
        val output: Path?,
        val ok: Boolean,
        val detail: String
    )

    // ── Encrypt ─────────────────────────────────────────────────────────

    suspend fun encryptFile(
        file: Path,
        recipientFingerprints: Collection<String>,
        signerFingerprint: String?,
        signerPassphrase: String?,
        armor: Boolean,
        onProgress: (Long, Long) -> Unit = NO_PROGRESS,
        isCancelled: () -> Boolean = NOT_CANCELLED
    ): FileOutcome = try {
        val rings = recipientFingerprints.map {
            repo.loadPublicKeyRing(it) ?: error(tr("d_file_err_recipient_ring", it.take(16)))
        }
        // The Phase A3 rule — a requested signature must never silently drop.
        val signerRing = signerFingerprint?.let {
            repo.loadSecretKeyRing(it) ?: error(tr("d_file_err_signing_key", it.take(16)))
        }
        // Write to a temp sibling and MOVE on success (D17): a cancel or crash leaves the temp,
        // which the catch deletes — never a half-written .gpg beside the source, never an
        // overwrite. Output name is resolved at the end, keeping the never-overwrite guarantee.
        val total = runCatching { Files.size(file) }.getOrDefault(-1L)
        val tmp = Files.createTempFile(file.parent, ".pgpony-enc", ".tmp")
        try {
            ProgressInputStream(Files.newInputStream(file), total, isCancelled, onProgress).use { input ->
                Files.newOutputStream(tmp).use { output ->
                    crypto.encryptStream(
                        input = input,
                        output = output,
                        recipientPublicKeys = rings,
                        signingSecretKey = signerRing,
                        passphrase = signerPassphrase,
                        filename = file.name,
                        armor = armor
                    )
                }
            }
        } catch (t: Throwable) {
            Files.deleteIfExists(tmp)
            throw t
        }
        val out = uniquePath(file.resolveSibling(file.name + if (armor) ".asc" else ".gpg"))
        Files.move(tmp, out, StandardCopyOption.REPLACE_EXISTING)
        FileOutcome(
            file, out, true,
            trQuantity("d_file_encrypted_to", recipientFingerprints.size) +
                (if (signerRing != null) tr("d_file_signed_suffix") else "")
        )
    } catch (t: Throwable) {
        cancelledOrError(file, t) { tr("d_file_err_encrypt") }
    }

    // ── Encrypt a folder (D16 / 2.0.0 §3a) ──────────────────────────────
    //
    // A dropped folder tars, then encrypts, in one pass: TarStreamer writes the archive into a
    // pipe that encryptStream reads, so a multi-gigabyte tree never lands in the heap AND the
    // plaintext tar never touches disk (no temp file to leak or clean up). The producer thread
    // carries any walk/IO failure across the pipe so the outcome reflects it.

    suspend fun encryptFolder(
        folder: Path,
        recipientFingerprints: Collection<String>,
        signerFingerprint: String?,
        signerPassphrase: String?,
        armor: Boolean,
        onProgress: (Long, Long) -> Unit = NO_PROGRESS,
        isCancelled: () -> Boolean = NOT_CANCELLED
    ): FileOutcome = try {
        val rings = recipientFingerprints.map {
            repo.loadPublicKeyRing(it) ?: error(tr("d_file_err_recipient_ring", it.take(16)))
        }
        val signerRing = signerFingerprint?.let {
            repo.loadSecretKeyRing(it) ?: error(tr("d_file_err_signing_key", it.take(16)))
        }
        val tarName = folder.fileName.toString() + ".tar"
        // A cheap stat walk gives a determinate total; tar headers add a little, but for a
        // progress bar the payload bytes are what the user watches move.
        val total = runCatching { folderSize(folder) }.getOrDefault(-1L)
        val tmp = Files.createTempFile(folder.parent, ".pgpony-enc", ".tmp")

        val piped = java.io.PipedInputStream(1 shl 16)
        val sink = java.io.PipedOutputStream(piped)
        val producerError = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val producer = Thread({
            try {
                sink.use { TarStreamer.archive(folder, it) }
            } catch (t: Throwable) {
                producerError.set(t)
            }
        }, "pgpony-tar-encrypt").apply { isDaemon = true; start() }

        try {
            ProgressInputStream(piped, total, isCancelled, onProgress).use { input ->
                Files.newOutputStream(tmp).use { output ->
                    crypto.encryptStream(
                        input = input,
                        output = output,
                        recipientPublicKeys = rings,
                        signingSecretKey = signerRing,
                        passphrase = signerPassphrase,
                        filename = tarName,
                        armor = armor
                    )
                }
            }
        } catch (t: Throwable) {
            producer.join()
            Files.deleteIfExists(tmp)
            throw t
        } finally {
            producer.join()
        }
        producerError.get()?.let { Files.deleteIfExists(tmp); throw it } // a walk failure fails the op

        val out = uniquePath(folder.resolveSibling(tarName + if (armor) ".asc" else ".gpg"))
        Files.move(tmp, out, StandardCopyOption.REPLACE_EXISTING)
        FileOutcome(
            folder, out, true,
            trQuantity("d_file_folder_encrypted", recipientFingerprints.size) +
                (if (signerRing != null) tr("d_file_signed_suffix") else "")
        )
    } catch (t: Throwable) {
        cancelledOrError(folder, t) { tr("d_file_err_encrypt") }
    }

    private fun folderSize(folder: Path): Long {
        var sum = 0L
        Files.walk(folder).use { s -> s.forEach { if (Files.isRegularFile(it)) sum += Files.size(it) } }
        return sum
    }

    // ── Decrypt ─────────────────────────────────────────────────────────

    /**
     * Decrypts three input shapes (D3c Fix1 — field report: a saved .eml failed here):
     *   1. A full .eml / PGP/MIME envelope — `MimeParser.pgpMimeEncryptedPayload` extracts the
     *      armored payload (same routing as the text Decrypt tab).
     *   2. An armored-message text file (.asc or any text carrying a PGP MESSAGE block).
     *   Both go through the byte path; if the plaintext is a MIME bundle, it unpacks into a
     *   sibling FOLDER — body.txt + each attachment as a real file.
     *   3. Anything else (binary .gpg/.pgp) — the original streaming path, heap-free.
     */
    suspend fun decryptFile(
        file: Path,
        passphrase: String?,
        onProgress: (Long, Long) -> Unit = NO_PROGRESS,
        isCancelled: () -> Boolean = NOT_CANCELLED
    ): FileOutcome = try {
        val all = repo.allKeys()
        val secretRings = all.filter { it.isKeyPair }.mapNotNull { repo.loadSecretKeyRing(it.fingerprint) }
        val publicRings = all.mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }

        val headText = peekText(file)
        val armoredFromText: String? = if (headText != null) {
            val fullText by lazy { Files.readString(file) }
            when {
                headText.contains("multipart/encrypted") || headText.contains("Content-Type:") ->
                    MimeParser.pgpMimeEncryptedPayload(fullText) ?: extractArmoredMessage(fullText)
                headText.contains(BEGIN_MESSAGE) -> extractArmoredMessage(fullText)
                else -> null
            }
        } else null

        if (armoredFromText != null) {
            // Byte path (armored text is base64-bounded in size).
            val result = crypto.decryptArmored(armoredFromText, secretRings, passphrase, publicRings)
            val sigNote = sigNote(result.signatureVerified, result.hasSignature, result.signerKeyID, result.signatureKeyIDRaw)
            val mime = MimeParser.parse(result.data)
            if (TarStreamer.looksLikeTar(result.data)) {
                // A folder encrypted with §3a arrives as a ustar tarball — extract it to a
                // sibling folder rather than dropping a raw .tar. Checked before MIME: a tar is
                // unambiguous by its magic, whereas MimeParser would happily mis-read tar bytes.
                extractTar(file, result.data.inputStream(), sigNote)
            } else if (mime != null && (mime.hasAttachments || !mime.body.isNullOrBlank())) {
                // Bundle → sibling folder with body + attachments as files.
                val outDir = uniquePath(file.resolveSibling(file.nameWithoutExtension))
                Files.createDirectories(outDir)
                var written = 0
                mime.body?.takeIf { it.isNotBlank() }?.let {
                    Files.writeString(uniquePath(outDir.resolve("body.txt")), it); written++
                }
                mime.attachments.forEach { att ->
                    val safe = att.filename.substringAfterLast('/').substringAfterLast('\\')
                        .ifBlank { "attachment" }
                    Files.write(uniquePath(outDir.resolve(safe)), att.data); written++
                }
                FileOutcome(file, outDir, true, trQuantity("d_file_decrypted_bundle", written) + sigNote)
            } else {
                val restoredName = result.filename
                    ?.takeIf { it.isNotBlank() && !it.contains('/') && !it.contains('\\') }
                    ?: defaultDecryptedName(file)
                val out = uniquePath(file.resolveSibling(restoredName))
                Files.write(out, result.data)
                FileOutcome(file, out, true, trQuantity("d_file_decrypted_bytes", result.data.size) + sigNote)
            }
        } else {
            // Streaming path for binary ciphertext. Progress is bytes read from the CIPHERTEXT
            // (the plaintext size isn't known ahead), a fine proxy for a moving bar.
            val total = runCatching { Files.size(file) }.getOrDefault(-1L)
            val tmp = Files.createTempFile(file.parent, ".pgpony-dec", ".tmp")
            val result = try {
                ProgressInputStream(Files.newInputStream(file), total, isCancelled, onProgress).use { input ->
                    Files.newOutputStream(tmp).use { output ->
                        crypto.decryptStream(input, output, secretRings, passphrase, publicRings)
                    }
                }
            } catch (t: Throwable) {
                Files.deleteIfExists(tmp)
                throw t
            }
            val sigNote = sigNote(result.signatureVerified, result.hasSignature, result.signerKeyID, result.signatureKeyIDRaw)
            // Peek the plaintext head: a §3a folder tarball extracts to a sibling folder,
            // streamed straight off the temp file so a huge archive never re-enters the heap.
            val head = Files.newInputStream(tmp).use { it.readNBytes(512) }
            if (TarStreamer.looksLikeTar(head)) {
                val outcome = Files.newInputStream(tmp).use { extractTar(file, it, sigNote) }
                Files.deleteIfExists(tmp)
                outcome
            } else {
                val restoredName = result.filename
                    ?.takeIf { it.isNotBlank() && !it.contains('/') && !it.contains('\\') }
                    ?: defaultDecryptedName(file)
                val out = uniquePath(file.resolveSibling(restoredName))
                Files.move(tmp, out, StandardCopyOption.REPLACE_EXISTING)
                FileOutcome(file, out, true, trQuantity("d_file_decrypted_bytes", result.bytesWritten) + sigNote)
            }
        }
    } catch (t: Throwable) {
        cancelledOrError(file, t) { tr("d_file_err_decrypt") }
    }

    /**
     * Map a caught throwable to an outcome: a user cancel (D17) reads as a neutral "cancelled"
     * line, not a red error — the partial output was already deleted by the op's inner catch.
     */
    private inline fun cancelledOrError(input: Path, t: Throwable, fallback: () -> String): FileOutcome =
        if (t is CancelledException) FileOutcome(input, null, false, tr("d_file_cancelled"))
        else FileOutcome(input, null, false, t.message ?: fallback())

    /**
     * Extract a decrypted ustar [tar] stream into a uniquely-named sibling folder of [file].
     * TarStreamer enforces the traversal / symlink guards; a hostile archive fails the whole
     * op with a named error rather than half-populating the folder. The destination is the
     * input name with its .tar(.gpg|.asc) suffix peeled off, so `docs.tar.gpg` → `docs/`.
     */
    private fun extractTar(file: Path, tar: java.io.InputStream, sigNote: String): FileOutcome {
        val stem = file.name
            .removeSuffix(".gpg").removeSuffix(".asc").removeSuffix(".pgp").removeSuffix(".tar")
            .ifBlank { file.nameWithoutExtension }
        val outDir = uniquePath(file.resolveSibling(stem))
        Files.createDirectories(outDir)
        val written = try {
            TarStreamer.extract(tar, outDir)
        } catch (t: Throwable) {
            // Leave the partial folder for the user to inspect; surface the reason.
            return FileOutcome(file, outDir, false, t.message ?: tr("d_file_err_decrypt"))
        }
        return FileOutcome(file, outDir, true, trQuantity("d_file_folder_extracted", written) + sigNote)
    }

    private fun defaultDecryptedName(file: Path): String = when (file.extension.lowercase()) {
        "gpg", "pgp", "asc", "eml" -> file.nameWithoutExtension
        else -> file.name + ".decrypted"
    }

    private fun sigNote(verified: Boolean, has: Boolean, keyId: String?, raw: Long?): String = when {
        verified -> tr("d_file_sig_verified") + (keyId?.let { tr("d_file_sig_id_suffix", it) } ?: "")
        has -> tr("d_file_sig_unheld") +
            (raw?.let { tr("d_file_sig_id_suffix", String.format("%016X", it)) } ?: "")
        else -> ""
    }

    /** First 16 KB as text if it looks like text (no NUL bytes), else null. */
    private fun peekText(file: Path): String? = runCatching {
        Files.newInputStream(file).use { ins ->
            val head = ins.readNBytes(16384)
            if (head.isEmpty() || head.any { it == 0.toByte() }) null
            else String(head, Charsets.ISO_8859_1)
        }
    }.getOrNull()

    // ── Detached signatures ─────────────────────────────────────────────

    suspend fun signFileDetached(
        file: Path,
        signerFingerprint: String,
        signerPassphrase: String?,
        armor: Boolean
    ): FileOutcome = try {
        val ring = repo.loadSecretKeyRing(signerFingerprint)
            ?: error(tr("d_file_err_signing_key", signerFingerprint.take(16)))
        val sig = Files.newInputStream(file).use { input ->
            SigningService.shared.signDetachedStream(input, ring, signerPassphrase, armor = armor)
        }
        val out = uniquePath(file.resolveSibling(file.name + if (armor) ".asc" else ".sig"))
        Files.write(out, sig)
        FileOutcome(file, out, true, tr("d_file_sig_written"))
    } catch (t: Throwable) {
        FileOutcome(file, null, false, t.message ?: tr("d_file_err_sign"))
    }

    // ── D7 — card-backed file operations ────────────────────────────────

    /**
     * Detached-sign [file] with the CARD (PSO:CDS). Same naming/never-overwrite rules as the
     * software path. Runs with the card connected; the session must be SELECTed.
     */
    fun signFileDetachedWithCard(
        file: Path,
        session: com.pgpony.android.crypto.card.OpenPgpCardSession,
        signingPublicKey: org.bouncycastle.openpgp.PGPPublicKey,
        pin: ByteArray,
        armor: Boolean
    ): FileOutcome = try {
        val sig = com.pgpony.android.crypto.card.CardSigningService.shared.signDetached(
            session, signingPublicKey, pin, Files.readAllBytes(file), armor = armor
        )
        val out = uniquePath(file.resolveSibling(file.name + if (armor) ".asc" else ".sig"))
        Files.write(out, sig)
        FileOutcome(file, out, true, tr("d_file_sig_written_card"))
    } catch (t: Throwable) {
        FileOutcome(file, null, false, t.message ?: tr("d_file_err_card_sign"))
    }

    /**
     * Decrypt [file] on the CARD (PSO:DECIPHER). Mirrors [decryptFile]'s shapes: .eml and
     * armored text are unwrapped first; the plaintext unpacks to a bundle folder when it's
     * MIME, or restores the embedded filename. CardDecryptService's decoder handles armored
     * and binary input alike, and its integrity gate matches the software path.
     */
    /**
     * The encrypted bytes for a file, unwrapping a .eml / PGP-MIME envelope or an armored-text
     * container to its payload first (so card-key matching and card decrypt see the same bytes
     * the software path would). Binary ciphertext passes through unchanged.
     */
    fun encryptedBytesForCard(file: Path): ByteArray {
        val headText = peekText(file) ?: return Files.readAllBytes(file)
        val fullText = Files.readString(file)
        val armored = when {
            headText.contains("multipart/encrypted") || headText.contains("Content-Type:") ->
                MimeParser.pgpMimeEncryptedPayload(fullText) ?: extractArmoredMessage(fullText)
            headText.contains(BEGIN_MESSAGE) -> extractArmoredMessage(fullText)
            else -> null
        }
        return armored?.toByteArray(Charsets.UTF_8) ?: Files.readAllBytes(file)
    }

    suspend fun decryptFileWithCard(
        file: Path,
        session: com.pgpony.android.crypto.card.OpenPgpCardSession,
        cardRing: org.bouncycastle.openpgp.PGPPublicKeyRing,
        pin: ByteArray
    ): FileOutcome = try {
        val publicRings = repo.allKeys().mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
        val encryptedBytes = encryptedBytesForCard(file)

        val result = com.pgpony.android.crypto.card.CardDecryptService.shared.decryptBytes(
            session, cardRing, pin, encryptedBytes, verificationKeys = publicRings
        )
        val sigNote = sigNote(
            result.signatureVerified, result.hadSignature,
            result.signerKeyID.takeIf { result.signerKnown }, null
        )
        val mime = MimeParser.parse(result.data)
        if (mime != null && (mime.hasAttachments || !mime.body.isNullOrBlank())) {
            val outDir = uniquePath(file.resolveSibling(file.nameWithoutExtension))
            Files.createDirectories(outDir)
            var written = 0
            mime.body?.takeIf { it.isNotBlank() }?.let {
                Files.writeString(uniquePath(outDir.resolve("body.txt")), it); written++
            }
            mime.attachments.forEach { att ->
                val safe = att.filename.substringAfterLast('/').substringAfterLast('\\')
                    .ifBlank { "attachment" }
                Files.write(uniquePath(outDir.resolve(safe)), att.data); written++
            }
            FileOutcome(file, outDir, true, trQuantity("d_file_decrypted_bundle_card", written) + sigNote)
        } else {
            val restoredName = result.filename
                ?.takeIf { it.isNotBlank() && !it.contains('/') && !it.contains('\\') }
                ?: defaultDecryptedName(file)
            val out = uniquePath(file.resolveSibling(restoredName))
            Files.write(out, result.data)
            FileOutcome(file, out, true, trQuantity("d_file_decrypted_bytes_card", result.data.size) + sigNote)
        }
    } catch (t: Throwable) {
        FileOutcome(file, null, false, t.message ?: tr("d_file_err_card_decrypt"))
    }

    /**
     * Encrypt [file] with the signature leg on the CARD — the vendored encryptStream's HW
     * Phase 3 params (compression off, same as Android's card path, so the card holds the
     * connection only for the AES pass).
     */
    suspend fun encryptFileWithCardSigner(
        file: Path,
        recipientFingerprints: Collection<String>,
        session: com.pgpony.android.crypto.card.OpenPgpCardSession,
        cardPin: ByteArray,
        cardSigningPublicKey: org.bouncycastle.openpgp.PGPPublicKey,
        armor: Boolean
    ): FileOutcome = try {
        val rings = recipientFingerprints.map {
            repo.loadPublicKeyRing(it) ?: error(tr("d_file_err_recipient_ring", it.take(16)))
        }
        val out = uniquePath(file.resolveSibling(file.name + if (armor) ".asc" else ".gpg"))
        Files.newInputStream(file).use { input ->
            Files.newOutputStream(out).use { output ->
                crypto.encryptStream(
                    input = input,
                    output = output,
                    recipientPublicKeys = rings,
                    filename = file.name,
                    armor = armor,
                    enableCompression = false,
                    cardSession = session,
                    cardPin = cardPin,
                    cardSigningPublicKey = cardSigningPublicKey
                )
            }
        }
        FileOutcome(
            file, out, true,
            trQuantity("d_file_encrypted_to_card", recipientFingerprints.size)
        )
    } catch (t: Throwable) {
        FileOutcome(file, null, false, t.message ?: tr("d_file_err_encrypt"))
    }

    suspend fun verifyFileDetached(signatureFile: Path, contentFile: Path): FileOutcome = try {
        val publicRings = repo.allKeys().mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
        val sigBytes = Files.readAllBytes(signatureFile)
        val result = Files.newInputStream(contentFile).use { content ->
            VerifyService.shared.verifyDetachedStream(sigBytes, content, publicRings)
        }
        when (result) {
            is VerificationResult.Verified -> FileOutcome(
                contentFile, null, true,
                tr(
                    "d_file_verify_ok", result.signerName ?: "",
                    result.signerEmail ?: "?", result.signerKeyID
                )
            )
            is VerificationResult.Invalid -> FileOutcome(
                contentFile, null, false, tr("d_file_verify_invalid")
            )
            is VerificationResult.UnknownSigner -> FileOutcome(
                contentFile, null, false, tr("d_file_verify_unknown_signer")
            )
            is VerificationResult.Unsigned -> FileOutcome(
                contentFile, null, false, tr("d_file_verify_unsigned")
            )
        }
    } catch (t: Throwable) {
        FileOutcome(contentFile, null, false, t.message ?: tr("d_file_err_verify"))
    }

    companion object {
        private const val BEGIN_MESSAGE = "-----BEGIN PGP MESSAGE-----"
        private const val END_MESSAGE = "-----END PGP MESSAGE-----"

        /** Defaults so the card paths and tests can call the ops without a progress/cancel arg. */
        val NO_PROGRESS: (Long, Long) -> Unit = { _, _ -> }
        val NOT_CANCELLED: () -> Boolean = { false }

        /** The armored MESSAGE block inside arbitrary surrounding text, or null. */
        fun extractArmoredMessage(text: String): String? {
            val begin = text.indexOf(BEGIN_MESSAGE)
            if (begin < 0) return null
            val end = text.indexOf(END_MESSAGE, begin)
            if (end < 0) return null
            return text.substring(begin, end + END_MESSAGE.length)
        }

        /** Never overwrite: file.gpg → file-1.gpg → file-2.gpg … */
        fun uniquePath(desired: Path): Path {
            if (!Files.exists(desired)) return desired
            val base = desired.nameWithoutExtension
            val ext = desired.extension.let { if (it.isBlank()) "" else ".$it" }
            var n = 1
            while (true) {
                val candidate = desired.resolveSibling("$base-$n$ext")
                if (!Files.exists(candidate)) return candidate
                n++
            }
        }

        /** Extensions that route a dropped/picked file toward Decrypt or Verify by default. */
        fun looksEncrypted(path: Path): Boolean =
            path.extension.lowercase() in setOf("gpg", "pgp", "asc")

        fun looksDetachedSig(path: Path): Boolean =
            path.extension.lowercase() in setOf("sig", "asc") &&
                Files.exists(path.resolveSibling(path.nameWithoutExtension))

        /**
         * Pair signatures with their content for verification: every .sig/.asc whose sibling
         * content file exists pairs automatically; otherwise exactly two selected files pair
         * as (signature, content). Empty when no pairing can be made.
         */
        fun pairDetached(files: List<Path>): List<Pair<Path, Path>> {
            val auto = files.filter { looksDetachedSig(it) }
                .map { it to it.resolveSibling(it.nameWithoutExtension) }
            if (auto.isNotEmpty()) return auto
            if (files.size == 2) {
                val sig = files.firstOrNull { it.extension.lowercase() in setOf("sig", "asc") }
                val content = files.firstOrNull { it != sig }
                if (sig != null && content != null) return listOf(sig to content)
            }
            return emptyList()
        }
    }
}
