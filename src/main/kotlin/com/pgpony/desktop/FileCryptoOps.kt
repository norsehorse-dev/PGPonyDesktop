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
//
// 3.0.0: every output is created new through SafeFiles (below). A name that is already taken,
// by a file, a folder or a link (dangling or not), moves on to the next numbered name, and a
// link at the destination is never followed. Decrypted files and folders are readable by their
// owner only, whichever path produced them. Names that come from a message (the literal
// filename, a MIME attachment name, a zip entry name) are reduced to a plain base name that is
// valid on every desktop OS, and a name the file system refuses falls back to the default name.

package com.pgpony.desktop

import com.pgpony.android.crypto.DecryptResult
import com.pgpony.android.crypto.DecryptStreamResult
import com.pgpony.android.crypto.LiteralFilename
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SecurityLimits
import com.pgpony.android.crypto.SignerEvaluator
import com.pgpony.android.crypto.SignerStatus
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.crypto.mime.MimeMessage
import com.pgpony.android.crypto.mime.MimeParser
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.FileSystemException
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.InvalidPathException
import java.nio.file.LinkOption
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileAttribute
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.extension
import kotlin.io.path.name
import kotlin.io.path.nameWithoutExtension

/** A source the caller opened itself (a watch rule opens its file without following links). */
class OpenedInput(val stream: InputStream, val size: Long)

class FileCryptoOps(
    private val repo: DesktopKeyRepository,
    private val crypto: PGPCryptoService = PGPCryptoService.shared
) {
    // 3.0.0: recipients, the expired-key rule and the signer (classical or composite ML-DSA)
    // are decided in one place for every encrypt path. See EncryptOps.
    private val encryptOps = EncryptOps(repo)

    data class FileOutcome(
        val input: Path,
        val output: Path?,
        val ok: Boolean,
        val detail: String
    )

    // ── Encrypt ─────────────────────────────────────────────────────────

    /**
     * [openInput], when given, opens [file] instead of a plain path open (the watch folders
     * open without following links and check what they opened). The source is opened before
     * anything is created, and the temp file is made in the output folder.
     */
    suspend fun encryptFile(
        file: Path,
        recipientFingerprints: Collection<String>,
        signerFingerprint: String?,
        signerPassphrase: String?,
        armor: Boolean,
        onProgress: (Long, Long) -> Unit = NO_PROGRESS,
        isCancelled: () -> Boolean = NOT_CANCELLED,
        outputDir: Path? = null,
        compositeInV1Decision: Boolean? = true,
        subkeyChoices: Map<String, Long> = emptyMap(),
        zip: Boolean = false,
        openInput: ((Path) -> OpenedInput)? = null
    ): FileOutcome = try {
        // The Phase A3 rule: a requested signature must never silently drop, so a signer that
        // cannot be loaded stops the op (EncryptOps.plan throws).
        val signer = signerFingerprint?.let {
            repo.byFingerprint(it) ?: error(tr("d_file_err_signing_key", it.take(16)))
        }
        val plan = encryptOps.plan(recipientFingerprints, signer, signerPassphrase, compositeInV1Decision, subkeyChoices)
        // Output beside the source, or in a rule's output directory (D18 watch folders).
        val outParent = outputDir?.also { Files.createDirectories(it) } ?: parentOf(file)
        val source = openInput?.invoke(file)
            ?: OpenedInput(Files.newInputStream(file), runCatching { Files.size(file) }.getOrDefault(-1L))
        val total = source.size
        // Write to a temp sibling and MOVE on success (D17): a cancel or crash leaves the temp,
        // which the catch deletes; never a half-written .gpg beside the source, never an
        // overwrite. Output name is resolved at the end, keeping the never-overwrite guarantee.
        var tmp: Path? = null
        try {
            tmp = Files.createTempFile(outParent, ".pgpony-enc", ".tmp")
            if (plan.needsBuffering) {
                // A composite ML-DSA signature has no streaming signer in the engine; the file
                // is read whole, as Android does (4.5.3), up to a fixed ceiling.
                if (total > EncryptOps.COMPOSITE_BUFFER_LIMIT) error(tr("d_file_err_composite_too_large"))
                val data = ProgressInputStream(source.stream, total, isCancelled, onProgress).use { it.readAllBytes() }
                Files.write(tmp, encryptOps.encryptBytes(plan, data, signerPassphrase, armor, file.name))
            } else {
                ProgressInputStream(source.stream, total, isCancelled, onProgress).use { input ->
                    Files.newOutputStream(tmp).use { output ->
                        encryptOps.encryptStream(plan, input, output, signerPassphrase, armor, file.name)
                    }
                }
            }
        } catch (t: Throwable) {
            tmp?.let { Files.deleteIfExists(it) }
            throw t
        } finally {
            runCatching { source.stream.close() }
        }
        val outName = file.name + if (armor) ".asc" else ".gpg"
        val out = placeOutput(tmp!!, outParent, outName, zip)
        FileOutcome(
            file, out, true,
            trQuantity("d_file_encrypted_to", recipientFingerprints.size) +
                (if (plan.signs) tr("d_file_signed_suffix") else "") + beyondDecryptLimitNote(total)
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
        isCancelled: () -> Boolean = NOT_CANCELLED,
        compositeInV1Decision: Boolean? = true,
        subkeyChoices: Map<String, Long> = emptyMap(),
        zip: Boolean = false
    ): FileOutcome = try {
        val signer = signerFingerprint?.let {
            repo.byFingerprint(it) ?: error(tr("d_file_err_signing_key", it.take(16)))
        }
        val plan = encryptOps.plan(recipientFingerprints, signer, signerPassphrase, compositeInV1Decision, subkeyChoices)
        val tarName = folder.fileName.toString() + ".tar"
        // A cheap stat walk gives a determinate total; tar headers add a little, but for a
        // progress bar the payload bytes are what the user watches move.
        val total = runCatching { folderSize(folder) }.getOrDefault(-1L)
        val parent = parentOf(folder)
        val tmp = Files.createTempFile(parent, ".pgpony-enc", ".tmp")

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
            if (plan.needsBuffering) {
                // Composite ML-DSA signer: the tar is built in memory under the same ceiling as
                // a single file (the engine has no streaming composite signer).
                if (total > EncryptOps.COMPOSITE_BUFFER_LIMIT) error(tr("d_file_err_composite_too_large"))
                val data = ProgressInputStream(piped, total, isCancelled, onProgress).use { it.readAllBytes() }
                Files.write(tmp, encryptOps.encryptBytes(plan, data, signerPassphrase, armor, tarName))
            } else {
                ProgressInputStream(piped, total, isCancelled, onProgress).use { input ->
                    Files.newOutputStream(tmp).use { output ->
                        encryptOps.encryptStream(plan, input, output, signerPassphrase, armor, tarName)
                    }
                }
            }
        } catch (t: Throwable) {
            // Unblock a producer still writing into the pipe, then wait for it.
            runCatching { piped.close() }
            producer.join()
            Files.deleteIfExists(tmp)
            throw t
        } finally {
            producer.join()
        }
        producerError.get()?.let { Files.deleteIfExists(tmp); throw it } // a walk failure fails the op

        val out = placeOutput(tmp, parent, tarName + if (armor) ".asc" else ".gpg", zip)
        FileOutcome(
            folder, out, true,
            trQuantity("d_file_folder_encrypted", recipientFingerprints.size) +
                (if (plan.signs) tr("d_file_signed_suffix") else "") + beyondDecryptLimitNote(total)
        )
    } catch (t: Throwable) {
        cancelledOrError(folder, t) { tr("d_file_err_encrypt") }
    }

    /**
     * Move the finished ciphertext [tmp] to [parent]/[name] (never overwriting), or with [zip]
     * wrap it first as the one entry of [name].zip (3.0.0, Android #31: transport packaging for
     * channels that mangle .gpg and .asc). [tmp] is gone either way.
     */
    private fun placeOutput(tmp: Path, parent: Path, name: String, zip: Boolean): Path {
        if (!zip) {
            try {
                return SafeFiles.moveToNew(tmp, parent, name)
            } catch (t: Throwable) {
                Files.deleteIfExists(tmp)
                throw t
            }
        }
        val zipped = Files.createTempFile(parent, ".pgpony-zip", ".tmp")
        try {
            Files.newOutputStream(zipped).use { sink ->
                ZipTransport.writeSingleEntry(sink, name) { entry ->
                    Files.newInputStream(tmp).use { it.copyTo(entry) }
                }
            }
            return SafeFiles.moveToNew(zipped, parent, name + ZipTransport.ZIP_SUFFIX)
        } catch (t: Throwable) {
            Files.deleteIfExists(zipped)
            throw t
        } finally {
            Files.deleteIfExists(tmp)
        }
    }

    /** Bytes of the regular files under [folder], links not followed. */
    private fun folderSize(folder: Path): Long {
        var sum = 0L
        Files.walk(folder).use { s ->
            s.forEach { p ->
                val a = runCatching {
                    Files.readAttributes(p, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                }.getOrNull()
                if (a != null && a.isRegularFile) sum += a.size()
            }
        }
        return sum
    }

    /**
     * The note an encrypt result carries when its plaintext is larger than PGPony's own
     * streaming decrypt accepts (SecurityLimits.MAX_STREAM_PLAINTEXT_BYTES). The ciphertext is
     * standard OpenPGP and gpg opens it; the user is told before relying on PGPony to.
     */
    private fun beyondDecryptLimitNote(total: Long): String =
        if (total > SecurityLimits.MAX_STREAM_PLAINTEXT_BYTES)
            tr("d_file_note_beyond_decrypt_limit", "${SecurityLimits.MAX_STREAM_PLAINTEXT_BYTES / (1024L * 1024 * 1024)} GB")
        else ""

    // ── Decrypt ─────────────────────────────────────────────────────────

    /**
     * Decrypts three input shapes (D3c Fix1 — field report: a saved .eml failed here):
     *   1. A full .eml / PGP/MIME envelope — `MimeParser.pgpMimeEncryptedPayload` extracts the
     *      armored payload (same routing as the text Decrypt tab).
     *   2. An armored-message text file (.asc or any text carrying a PGP MESSAGE block).
     *   Both go through the byte path; if the plaintext is a MIME bundle, it unpacks into a
     *   sibling FOLDER: body.txt + each attachment as a real file. An armored file too large
     *   for the byte path, and holding nothing but the armored message, goes to the stream.
     *   3. Anything else (binary .gpg/.pgp) — the original streaming path, heap-free.
     *   4. (3.0.0, Android #31) A .zip holding one of the above: see [decryptZip].
     */
    suspend fun decryptFile(
        file: Path,
        passphrase: String?,
        onProgress: (Long, Long) -> Unit = NO_PROGRESS,
        isCancelled: () -> Boolean = NOT_CANCELLED,
        selected: String? = null
    ): FileOutcome =
        if (ZipTransport.looksLikeZip(file)) decryptZip(file, passphrase, onProgress, isCancelled, selected)
        else decryptFileDirect(file, passphrase, onProgress, isCancelled, selected)

    /**
     * A .zip holding one PGP message (3.0.0, Android #31 and 4.4.1 audit item 9). The entry is
     * extracted, bounded, into a private scratch folder beside the zip and decrypted there; what
     * that produced moves out beside the zip, and the scratch folder is always removed. No PGP
     * entry, or several, is reported rather than guessed at.
     */
    private suspend fun decryptZip(
        file: Path,
        passphrase: String?,
        onProgress: (Long, Long) -> Unit,
        isCancelled: () -> Boolean,
        selected: String?
    ): FileOutcome {
        val parent = parentOf(file)
        val scratch = try {
            Files.createTempDirectory(parent, ".pgpony-zip", *SafeFiles.dirAttrs(ownerOnly = true))
        } catch (t: Throwable) {
            return cancelledOrError(file, t) { tr("decrypt_zip_failed") }
        }
        return try {
            val staging = scratch.resolve(".entry")
            val found = Files.newInputStream(file).use { input ->
                Files.newOutputStream(staging, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use {
                    ZipTransport.extractSinglePgpEntry(input, it)
                }
            }
            when (found) {
                ZipTransport.Found.None -> FileOutcome(file, null, false, tr("decrypt_zip_no_pgp"))
                ZipTransport.Found.Several -> FileOutcome(file, null, false, tr("decrypt_zip_multiple"))
                is ZipTransport.Found.One -> {
                    // The entry keeps its (plain) name, so the default output name follows it;
                    // a name that is not a plain child of the scratch folder gets a fixed one.
                    val wanted = SafeFiles.plainName(found.name) ?: "message.gpg"
                    val entry = SafeFiles.childOrNull(scratch, wanted) ?: scratch.resolve("message.gpg")
                    Files.move(staging, entry)
                    val inner = decryptFileDirect(entry, passphrase, onProgress, isCancelled, selected)
                    val produced = inner.output
                    if (produced == null || !inner.ok) {
                        inner.copy(input = file, output = null)
                    } else {
                        val out = SafeFiles.moveToNew(produced, parent, produced.fileName.toString())
                        inner.copy(input = file, output = out)
                    }
                }
            }
        } catch (t: Throwable) {
            cancelledOrError(file, t) { tr("decrypt_zip_failed") }
        } finally {
            runCatching {
                Files.walk(scratch).use { walk ->
                    walk.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
                }
            }
        }
    }

    private suspend fun decryptFileDirect(
        file: Path,
        passphrase: String?,
        onProgress: (Long, Long) -> Unit,
        isCancelled: () -> Boolean,
        selected: String?
    ): FileOutcome = try {
        // 3.0.0 (plan 3.7): [selected], its fallbacks, then the rest unless strict.
        val keys = repo.decryptKeys(selected)
        val secretRings = keys.secretRings
        val publicRings = keys.verificationRings
        val dir = parentOf(file)

        val headText = peekText(file)
        val armoredFromText: String? = if (headText != null) {
            val isMime = headText.contains("multipart/encrypted") || headText.contains("Content-Type:")
            val isArmored = headText.contains(BEGIN_MESSAGE)
            val size = runCatching { Files.size(file) }.getOrDefault(0L)
            when {
                !isMime && !isArmored -> null
                // Too large to read as text: a bare armored message streams (the stream decoder
                // reads armor); anything wrapped around it cannot be unwrapped without the heap.
                size > MAX_TEXT_FILE_BYTES ->
                    if (!isMime && startsWithArmor(headText)) null else error(tr("d_file_err_text_too_large"))
                isMime -> {
                    val fullText = Files.readString(file, Charsets.ISO_8859_1)
                    MimeParser.pgpMimeEncryptedPayload(fullText) ?: extractArmoredMessage(fullText)
                }
                else -> extractArmoredMessage(Files.readString(file, Charsets.ISO_8859_1))
            }
        } else null

        if (armoredFromText != null) {
            // Byte path (armored text is base64-bounded in size).
            // Stage 4b: a blank passphrase uses each key's remembered one.
            val opened = DecryptOrder.cascadeKeys(keys, passphrase, PassphraseCache::get) { secret, composite, pass ->
                crypto.decryptArmored(armoredFromText, secret, pass, publicRings, composite)
            }
            repo.rememberOpened(opened.fingerprint, passphrase)
            val result = opened.value
            val sigNote = SignatureSummary.fileNote(DecryptSignature.of(repo, result))
            val mime = MimeParser.parse(result.data)
            if (TarStreamer.looksLikeTar(result.data)) {
                // A folder encrypted with §3a arrives as a ustar tarball — extract it to a
                // sibling folder rather than dropping a raw .tar. Checked before MIME: a tar is
                // unambiguous by its magic, whereas MimeParser would happily mis-read tar bytes.
                extractTar(file, result.data.inputStream(), result.data.size.toLong(), sigNote)
            } else if (mime != null && (mime.hasAttachments || !mime.body.isNullOrBlank())) {
                writeBundle(file, mime, "d_file_decrypted_bundle", sigNote)
            } else {
                val out = SafeFiles.writeNewNamed(dir, result.filename, defaultDecryptedName(file), result.data, ownerOnly = true)
                FileOutcome(file, out, true, trQuantity("d_file_decrypted_bytes", result.data.size) + sigNote)
            }
        } else {
            // Streaming path for binary ciphertext. Progress is bytes read from the CIPHERTEXT
            // (the plaintext size isn't known ahead), a fine proxy for a moving bar.
            val total = runCatching { Files.size(file) }.getOrDefault(-1L)
            // Stage 4b: one passphrase for the one pass over the stream. Nothing typed means the
            // remembered passphrase of a key the message names as a recipient.
            val recipients = recipientEntries(file, keys)
            val streamPassphrase = passphrase
                ?: recipients.firstNotNullOfOrNull { PassphraseCache.get(it.fingerprint) }
            // The plaintext goes to an owner-only temp file and is published only after the
            // engine returned (integrity and message structure checked). Whatever happens after
            // that, the temp file is either moved into place or deleted.
            // The temp file is written and read back through the handle that created it.
            val tmp = SafeFiles.openTemp(dir, ownerOnly = true)
            var moved = false
            try {
                val result = ProgressInputStream(Files.newInputStream(file), total, isCancelled, onProgress).use { input ->
                    java.io.BufferedOutputStream(tmp.output(), 1 shl 16).use { output ->
                        // 3.0.0 (Android 4.5.0, #36): the streaming path gets the raw composite and
                        // v4 algo-35 secret rings too, so a file encrypted to such a key opens
                        // here the same as pasted text does.
                        // A stream cannot be re-read, so no cascade here: the order alone.
                        crypto.decryptStream(
                            input, output, secretRings, streamPassphrase, publicRings, keys.compositeRings
                        )
                    }
                }
                repo.rememberOpened(recipients.singleOrNull()?.fingerprint, passphrase)
                val sigNote = SignatureSummary.fileNote(DecryptSignature.of(repo, result))
                // Peek the plaintext head: a §3a folder tarball extracts to a sibling folder,
                // streamed straight off the temp file so a huge archive never re-enters the heap.
                val head = tmp.input().readNBytes(512)
                if (TarStreamer.looksLikeTar(head)) {
                    extractTar(file, tmp.input(), tmp.size(), sigNote)
                } else {
                    tmp.close()
                    val out = SafeFiles.moveToNewNamed(tmp.path, dir, result.filename, defaultDecryptedName(file))
                    moved = true
                    FileOutcome(file, out, true, trQuantity("d_file_decrypted_bytes", result.bytesWritten) + sigNote)
                }
            } finally {
                runCatching { tmp.close() }
                if (!moved) Files.deleteIfExists(tmp.path)
            }
        }
    } catch (t: Throwable) {
        val explained = if (t is CancelledException) t else repo.explainDecryptFailure(
            { Files.newInputStream(file).use { crypto.inspectEncryptedMessage(it).publicKeyIDs } }, selected, t
        )
        cancelledOrError(file, explained) { tr("d_file_err_decrypt") }
    }

    /**
     * A decrypted MIME bundle as a new owner-only sibling folder of [file]: body.txt plus each
     * attachment, every name reduced to a plain base name.
     */
    private fun writeBundle(file: Path, mime: MimeMessage, countKey: String, sigNote: String): FileOutcome {
        val stem = SafeFiles.plainName(file.nameWithoutExtension) ?: "decrypted"
        val outDir = SafeFiles.createNewDir(parentOf(file), stem, ownerOnly = true)
        var written = 0
        mime.body?.takeIf { it.isNotBlank() }?.let {
            SafeFiles.writeNew(outDir, "body.txt", it.toByteArray(Charsets.UTF_8), ownerOnly = true); written++
        }
        mime.attachments.forEach { att ->
            SafeFiles.writeNewNamed(outDir, att.filename, "attachment", att.data, ownerOnly = true); written++
        }
        return FileOutcome(file, outDir, true, trQuantity(countKey, written) + sigNote)
    }

    /**
     * Map a caught throwable to an outcome: a user cancel (D17) reads as a neutral "cancelled"
     * line, not a red error — the partial output was already deleted by the op's inner catch.
     */
    private inline fun cancelledOrError(input: Path, t: Throwable, fallback: () -> String): FileOutcome =
        if (t is CancelledException) FileOutcome(input, null, false, tr("d_file_cancelled"))
        else FileOutcome(input, null, false, t.message ?: fallback())

    /**
     * Extract a decrypted ustar [tar] stream of [size] bytes into a new owner-only sibling
     * folder of [file]. TarStreamer enforces the traversal and link guards; a hostile archive
     * fails the whole op with a named error rather than half-populating the folder. The
     * destination is the input name with its .tar(.gpg|.asc) suffix peeled off, so
     * `docs.tar.gpg` → `docs/`.
     */
    private fun extractTar(file: Path, tar: InputStream, size: Long, sigNote: String): FileOutcome {
        val dir = parentOf(file)
        // The extracted files take about as much room as the archive; say so up front instead
        // of filling the volume and failing halfway.
        val free = runCatching { Files.getFileStore(dir).usableSpace }.getOrDefault(Long.MAX_VALUE)
        if (size > free) error(tr("d_file_err_no_space"))
        val stem = file.name
            .removeSuffix(".gpg").removeSuffix(".asc").removeSuffix(".pgp").removeSuffix(".tar")
            .ifBlank { file.nameWithoutExtension }
        val outDir = SafeFiles.createNewDir(dir, SafeFiles.plainName(stem) ?: "decrypted", ownerOnly = true)
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
    }.let { SafeFiles.plainName(it) ?: "decrypted" }

    /**
     * Stage 4b: our keys the message names as recipients, or every key when it names none we
     * can match (a hidden recipient, or a key BouncyCastle cannot list).
     */
    private fun recipientEntries(file: Path, keys: DecryptKeys): List<DecryptKeys.Entry> {
        val ids = runCatching {
            Files.newInputStream(file).use { crypto.inspectEncryptedMessage(it).publicKeyIDs }
        }.getOrDefault(emptyList()).toSet()
        val named = keys.entries.filter { e ->
            e.secretRing?.publicKeys?.asSequence()?.any { it.keyID in ids } == true
        }
        return named.ifEmpty { keys.entries }
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
        val signer = repo.byFingerprint(signerFingerprint)
            ?: error(tr("d_file_err_signing_key", signerFingerprint.take(16)))
        KeyUsePolicy.requireUsable(emptyList(), signer)
        val sig = if (signer.algorithm.isCompositeSign) {
            // 3.0.0 (Android 4.5.3, #65): a composite ML-DSA key signs files through the
            // composite signer; the classical stream signer cannot see an ML-DSA key.
            val info = repo.loadCompositeKeyInfo(signer.fingerprint, signerPassphrase?.toCharArray())
                ?: error(tr("d_file_err_signing_key", signerFingerprint.take(16)))
            val secret = info.compositeSecret ?: error(tr("d_file_err_signing_key", signerFingerprint.take(16)))
            if (Files.size(file) > EncryptOps.COMPOSITE_BUFFER_LIMIT) error(tr("d_file_err_composite_too_large"))
            val data = Files.readAllBytes(file)
            if (armor) com.pgpony.android.crypto.pqc.CompositeDocumentSigner
                .signDetachedArmored(info.suite, secret, info.fingerprint, data).toByteArray(Charsets.UTF_8)
            else com.pgpony.android.crypto.pqc.CompositeDocumentSigner
                .signDetached(info.suite, secret, info.fingerprint, data)
        } else {
            val ring = repo.loadSecretKeyRing(signerFingerprint)
                ?: error(tr("d_file_err_signing_key", signerFingerprint.take(16)))
            Files.newInputStream(file).use { input ->
                SigningService.shared.signDetachedStream(input, ring, signerPassphrase, armor = armor)
            }
        }
        val out = SafeFiles.writeNew(parentOf(file), file.name + if (armor) ".asc" else ".sig", sig, ownerOnly = false)
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
        val out = SafeFiles.writeNew(parentOf(file), file.name + if (armor) ".asc" else ".sig", sig, ownerOnly = false)
        FileOutcome(file, out, true, tr("d_file_sig_written_card"))
    } catch (t: Throwable) {
        FileOutcome(file, null, false, t.message ?: tr("d_file_err_card_sign"))
    }

    /**
     * The encrypted bytes for a file, unwrapping a .eml / PGP-MIME envelope or an armored-text
     * container to its payload first (so card-key matching and card decrypt see the same bytes
     * the software path would). Binary ciphertext passes through unchanged. The card path
     * works in memory, so a file past [MAX_CARD_INPUT_BYTES] is refused here (the software
     * path streams it).
     */
    fun encryptedBytesForCard(file: Path): ByteArray {
        if (Files.size(file) > MAX_CARD_INPUT_BYTES) error(tr("d_file_err_card_too_large"))
        val headText = peekText(file) ?: return Files.readAllBytes(file)
        val fullText = Files.readString(file, Charsets.ISO_8859_1)
        val armored = when {
            headText.contains("multipart/encrypted") || headText.contains("Content-Type:") ->
                MimeParser.pgpMimeEncryptedPayload(fullText) ?: extractArmoredMessage(fullText)
            headText.contains(BEGIN_MESSAGE) -> extractArmoredMessage(fullText)
            else -> null
        }
        return armored?.toByteArray(Charsets.ISO_8859_1) ?: Files.readAllBytes(file)
    }

    /**
     * Decrypt [file] on the CARD (PSO:DECIPHER). Mirrors [decryptFile]'s shapes: .eml and
     * armored text are unwrapped first; the plaintext unpacks to a bundle folder when it's
     * MIME, or restores the embedded filename. CardDecryptService's decoder handles armored
     * and binary input alike, and its integrity gate matches the software path.
     */
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
        val sigNote = SignatureSummary.fileNote(SignatureSummary.ofCard(repo, result, publicRings))
        val mime = MimeParser.parse(result.data)
        if (mime != null && (mime.hasAttachments || !mime.body.isNullOrBlank())) {
            writeBundle(file, mime, "d_file_decrypted_bundle_card", sigNote)
        } else {
            val out = SafeFiles.writeNewNamed(parentOf(file), result.filename, defaultDecryptedName(file), result.data, ownerOnly = true)
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
        KeyUsePolicy.requireUsable(recipientFingerprints.mapNotNull { repo.byFingerprint(it) }, null)
        val recipients = repo.requireRecipients(recipientFingerprints)
        val dir = parentOf(file)
        val tmp = Files.createTempFile(dir, ".pgpony-enc", ".tmp")
        try {
            Files.newInputStream(file).use { input ->
                Files.newOutputStream(tmp).use { output ->
                    crypto.encryptStream(
                        input = input,
                        output = output,
                        recipientPublicKeys = recipients.rings,
                        v4Algo35Recipients = recipients.v4Algo35,
                        filename = file.name,
                        armor = armor,
                        enableCompression = false,
                        cardSession = session,
                        cardPin = cardPin,
                        cardSigningPublicKey = cardSigningPublicKey
                    )
                }
            }
        } catch (t: Throwable) {
            Files.deleteIfExists(tmp)
            throw t
        }
        val out = placeOutput(tmp, dir, file.name + if (armor) ".asc" else ".gpg", zip = false)
        FileOutcome(
            file, out, true,
            trQuantity("d_file_encrypted_to_card", recipientFingerprints.size)
        )
    } catch (t: Throwable) {
        FileOutcome(file, null, false, t.message ?: tr("d_file_err_encrypt"))
    }

    suspend fun verifyFileDetached(signatureFile: Path, contentFile: Path): FileOutcome = try {
        val sigBytes = Files.readAllBytes(signatureFile)
        val contentBytes = Files.readAllBytes(contentFile)
        // Composite ML-DSA (RFC 9980) detached signatures verify whole-document; BouncyCastle
        // cannot parse them, so try the composite path first and fall back to VerifyService.
        val result = DesktopCompositeVerify.verifyDetached(repo, sigBytes, contentBytes)
            ?: run {
                val publicRings = repo.allKeys().mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
                contentBytes.inputStream().use { content ->
                    VerifyService.shared.verifyDetachedStream(sigBytes, content, publicRings)
                }
            }
        when (result) {
            is VerificationResult.Verified -> {
                // 3.0.0 (Android 4.5.3, #57): valid, but say so when the signer key is unconfirmed.
                val confirmed = SignatureSummary.fromVerification(repo, result).state == SignatureSummary.State.VERIFIED
                FileOutcome(
                    contentFile, null, true,
                    tr(
                        if (confirmed) "d_file_verify_ok" else "d_file_verify_ok_unconfirmed",
                        result.signerName ?: "", result.signerEmail ?: "?", result.signerKeyID
                    ) + SignatureSummary.weakNote(result.signerWeakKey, null)
                )
            }
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

        /**
         * Text files (armored messages, .eml) up to this size are read whole; a larger bare
         * armored message goes to the streaming decrypt instead. The in-memory decrypt caps its
         * plaintext at SecurityLimits.MAX_MESSAGE_PLAINTEXT_BYTES anyway.
         */
        internal const val MAX_TEXT_FILE_BYTES = 64L * 1024 * 1024

        /** The card path decrypts in memory; larger files are left to the software stream. */
        internal const val MAX_CARD_INPUT_BYTES = 2 * SecurityLimits.MAX_MESSAGE_PLAINTEXT_BYTES

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

        /** True when the first non-blank line of [head] is the armored message header. */
        internal fun startsWithArmor(head: String): Boolean =
            head.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() } == BEGIN_MESSAGE

        /** The folder [p] sits in (the current folder for a bare relative name). */
        internal fun parentOf(p: Path): Path = p.toAbsolutePath().normalize().parent
            ?: throw IllegalArgumentException("no parent folder: $p")

        /**
         * Never overwrite: file.gpg → file-1.gpg → file-2.gpg … A name held by anything,
         * including a dangling link, counts as taken. Only a hint: the writers in [SafeFiles]
         * create the file new and move on when the name was taken in the meantime.
         */
        fun uniquePath(desired: Path): Path {
            if (!Files.exists(desired, LinkOption.NOFOLLOW_LINKS)) return desired
            var n = 1
            while (true) {
                val candidate = SafeFiles.numbered(desired, n)
                if (!Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) return candidate
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

/**
 * Creating outputs without trusting what already sits at the name.
 *
 * Every write here creates its file new (O_EXCL), which also refuses a link at the name, and
 * moves on to the next numbered name when the name is taken. A finished temp file is moved into
 * place by first creating the final name new, then renaming the temp over that placeholder, so
 * the rename can never land on (or through) anything but the placeholder. Folders are created
 * with createDirectory, which fails on anything already there. Owner-only files are rw-------
 * and owner-only folders rwx------ wherever the file system has POSIX permissions.
 */
internal object SafeFiles {

    /** Longest name, in UTF-8 bytes, taken from a message (file systems allow 255). */
    private const val MAX_NAME_BYTES = 200

    /** How many numbered names are tried before giving up. */
    private const val MAX_ATTEMPTS = 10_000

    private val posix: Boolean by lazy {
        runCatching { FileSystems.getDefault().supportedFileAttributeViews().contains("posix") }.getOrDefault(false)
    }

    fun fileAttrs(ownerOnly: Boolean): Array<FileAttribute<*>> =
        if (ownerOnly && posix) arrayOf(PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        else emptyArray()

    fun dirAttrs(ownerOnly: Boolean): Array<FileAttribute<*>> =
        if (ownerOnly && posix) arrayOf(PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        else emptyArray()

    /**
     * [raw] (a name a message chose) as a plain base name that every desktop OS accepts as one
     * path component, at most [MAX_NAME_BYTES] UTF-8 bytes, or null when nothing usable is left.
     */
    fun plainName(raw: String?): String? {
        val base = LiteralFilename.sanitize(raw) ?: return null
        val fitted = fitBytes(base)
        if (fitted.isEmpty() || fitted == "." || fitted == "..") return null
        return try {
            val p = Path.of(fitted)
            if (p.nameCount == 1 && p.fileName.toString() == fitted && !p.isAbsolute && p.root == null) fitted else null
        } catch (_: InvalidPathException) {
            null
        }
    }

    /** [name] shortened to [MAX_NAME_BYTES] UTF-8 bytes at a character boundary, keeping a short extension. */
    private fun fitBytes(name: String): String {
        if (name.toByteArray(Charsets.UTF_8).size <= MAX_NAME_BYTES) return name
        val dot = name.lastIndexOf('.')
        val ext = if (dot > 0 && name.length - dot <= 16) name.substring(dot) else ""
        val stem = if (ext.isEmpty()) name else name.substring(0, dot)
        val budget = MAX_NAME_BYTES - ext.toByteArray(Charsets.UTF_8).size
        val sb = StringBuilder()
        var used = 0
        var i = 0
        while (i < stem.length) {
            val cp = stem.codePointAt(i)
            val len = String(Character.toChars(cp)).toByteArray(Charsets.UTF_8).size
            if (used + len > budget) break
            sb.appendCodePoint(cp)
            used += len
            i += Character.charCount(cp)
        }
        return (sb.toString().trimEnd('.', ' ') + ext).trimEnd('.', ' ')
    }

    /** [dir]/[name] when that is a direct child of [dir], else null. */
    fun childOrNull(dir: Path, name: String): Path? = try {
        val base = dir.toAbsolutePath().normalize()
        val child = base.resolve(name).normalize()
        if (child.parent == base && child.fileName?.toString() == name) child else null
    } catch (_: InvalidPathException) {
        null
    }

    /** report.pdf → report-[n].pdf, beside [desired]. */
    fun numbered(desired: Path, n: Int): Path {
        if (n == 0) return desired
        val base = desired.nameWithoutExtension
        val ext = desired.extension.let { if (it.isBlank()) "" else ".$it" }
        return desired.resolveSibling("$base-$n$ext")
    }

    private fun candidates(dir: Path, name: String): Sequence<Path> {
        val first = childOrNull(dir, name) ?: throw IllegalArgumentException("not a plain file name: $name")
        return (0 until MAX_ATTEMPTS).asSequence().map { numbered(first, it) }
    }

    private fun createOptions(): Set<OpenOption> =
        setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)

    /** A new file in [dir] named [name] (or the next free numbered name), open for writing. */
    fun createNew(dir: Path, name: String, ownerOnly: Boolean): Pair<Path, OutputStream> {
        for (candidate in candidates(dir, name)) {
            try {
                val ch = Files.newByteChannel(candidate, createOptions(), *fileAttrs(ownerOnly))
                return candidate to Channels.newOutputStream(ch)
            } catch (_: FileAlreadyExistsException) {
                continue
            }
        }
        throw FileAlreadyExistsException(dir.resolve(name).toString())
    }

    /** Write [bytes] to a new file in [dir] (see [createNew]); a failed write leaves nothing. */
    fun writeNew(dir: Path, name: String, bytes: ByteArray, ownerOnly: Boolean): Path {
        val (path, out) = createNew(dir, name, ownerOnly)
        try {
            out.use { it.write(bytes) }
        } catch (t: Throwable) {
            Files.deleteIfExists(path)
            throw t
        }
        return path
    }

    /**
     * [writeNew] under the message-chosen [wanted] name, or [fallback] when [wanted] is unusable
     * or the file system refuses it.
     */
    fun writeNewNamed(dir: Path, wanted: String?, fallback: String, bytes: ByteArray, ownerOnly: Boolean): Path =
        withFallbackName(wanted, fallback) { writeNew(dir, it, bytes, ownerOnly) }

    /**
     * Move the finished temp file [src] (same folder or file system as [dir]) to a new name in
     * [dir]. The name is reserved first by creating it new, then [src] is renamed over the
     * reservation. A folder is moved with a plain rename, which fails on anything already there.
     */
    fun moveToNew(src: Path, dir: Path, name: String): Path {
        if (Files.isDirectory(src, LinkOption.NOFOLLOW_LINKS)) {
            for (candidate in candidates(dir, name)) {
                try {
                    return Files.move(src, candidate)
                } catch (_: FileAlreadyExistsException) {
                    continue
                }
            }
            throw FileAlreadyExistsException(dir.resolve(name).toString())
        }
        for (candidate in candidates(dir, name)) {
            try {
                Files.newByteChannel(candidate, createOptions(), *fileAttrs(ownerOnly = true)).close()
            } catch (_: FileAlreadyExistsException) {
                continue
            }
            try {
                try {
                    Files.move(src, candidate, StandardCopyOption.ATOMIC_MOVE)
                } catch (_: AtomicMoveNotSupportedException) {
                    Files.move(src, candidate, StandardCopyOption.REPLACE_EXISTING)
                }
                return candidate
            } catch (t: Throwable) {
                runCatching { Files.deleteIfExists(candidate) }
                throw t
            }
        }
        throw FileAlreadyExistsException(dir.resolve(name).toString())
    }

    /** [moveToNew] under the message-chosen [wanted] name, or [fallback] (see [writeNewNamed]). */
    fun moveToNewNamed(src: Path, dir: Path, wanted: String?, fallback: String): Path =
        withFallbackName(wanted, fallback) { moveToNew(src, dir, it) }

    /**
     * A new temp file in [dir] with a random hidden name, created new and kept open: it is
     * written and read back through the handle that created it, so swapping the name for
     * another file in a shared folder can neither receive the bytes nor feed different ones
     * back. [OpenTemp.path] is for the final rename only.
     */
    fun openTemp(dir: Path, ownerOnly: Boolean): OpenTemp {
        val rnd = java.security.SecureRandom()
        val options = setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE)
        repeat(100) {
            val p = dir.resolve(".pgpony-" + java.lang.Long.toHexString(rnd.nextLong()) + ".tmp")
            try {
                return OpenTemp(p, FileChannel.open(p, options, *fileAttrs(ownerOnly)))
            } catch (_: FileAlreadyExistsException) {
                // try another name
            }
        }
        throw FileAlreadyExistsException(dir.toString())
    }

    /** An open temp file (see [openTemp]). Closing it leaves the file; delete or move [path]. */
    class OpenTemp(val path: Path, val channel: FileChannel) : java.io.Closeable {

        /** Writes at the channel's position; closing the stream leaves the channel open. */
        fun output(): OutputStream = object : OutputStream() {
            override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)
            override fun write(b: ByteArray, off: Int, len: Int) {
                val buf = ByteBuffer.wrap(b, off, len)
                while (buf.hasRemaining()) channel.write(buf)
            }
        }

        /** Reads from the start of the file, through the same handle; closing it leaves the channel open. */
        fun input(): InputStream = object : InputStream() {
            private var pos = 0L
            override fun read(): Int {
                val one = ByteArray(1)
                return if (read(one, 0, 1) <= 0) -1 else one[0].toInt() and 0xFF
            }
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (len == 0) return 0
                val n = channel.read(ByteBuffer.wrap(b, off, len), pos)
                if (n > 0) pos += n
                return n
            }
        }

        fun size(): Long = channel.size()

        override fun close() = channel.close()
    }

    /**
     * Put the finished temp file [tmp] at [target], an output the user named explicitly,
     * replacing what is there. The rename replaces a link at [target] itself and never writes
     * through it.
     */
    fun replaceInto(tmp: Path, target: Path) {
        try {
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING)
        }
    }

    /** A new folder in [dir] named [name] or the next free numbered name. */
    fun createNewDir(dir: Path, name: String, ownerOnly: Boolean): Path {
        for (candidate in candidates(dir, name)) {
            try {
                return Files.createDirectory(candidate, *dirAttrs(ownerOnly))
            } catch (_: FileAlreadyExistsException) {
                continue
            }
        }
        throw FileAlreadyExistsException(dir.resolve(name).toString())
    }

    private inline fun <T> withFallbackName(wanted: String?, fallback: String, op: (String) -> T): T {
        val name = plainName(wanted)
        if (name == null || name == fallback) return op(fallback)
        return try {
            op(name)
        } catch (e: FileAlreadyExistsException) {
            throw e
        } catch (_: FileSystemException) {
            // Too long for this file system, or a name it refuses: the default name instead.
            op(fallback)
        } catch (_: InvalidPathException) {
            op(fallback)
        } catch (_: IllegalArgumentException) {
            op(fallback)
        }
    }
}

/**
 * The signature reading for a decrypt result: SignatureSummary's whole-result entry points,
 * which name the signer by the key that verified (the engine's signerPrimaryFingerprint), never
 * by the key ID a signature packet claims, and read a held signer whose signature did not pass
 * as INVALID.
 */
internal object DecryptSignature {

    suspend fun of(repo: DesktopKeyRepository, r: DecryptStreamResult): SignatureSummary.Summary =
        SignatureSummary.ofStream(repo, r)

    suspend fun of(repo: DesktopKeyRepository, r: DecryptResult): SignatureSummary.Summary =
        SignatureSummary.ofDecrypt(repo, r)

    /** Plain-English reason for a graded status that is not VERIFIED (the CLI prints it). */
    fun reason(status: SignerStatus): String = SignerEvaluator.reason(status)
}
