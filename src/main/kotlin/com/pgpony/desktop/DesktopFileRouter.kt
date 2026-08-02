// DesktopFileRouter.kt
// PGPony Desktop — D9: the open-a-file decision tree. The desktop counterpart of Android's
// IntentHandler.handleFileUri, byte-for-byte the same routing so a file behaves identically
// wherever PGPony opens it: double-click a file association, a CLI file argument, a second
// launch forwarded by the single-instance guard, or a menu "Open…". Drag-drop keeps its own
// existing Files-tab path (the user has already chosen a bulk operation there).
//
// Same classification order and thresholds as Android:
//   .pgpony / "PGPony Backup" / "Passphrase-Format" (OpenKeychain) → Restore
//   multipart/encrypted (.eml)                                     → Decrypt (file)
//   armored KEY block                                             → Import (size-exempt)
//   armored, ≤32KB                                                → detached-sig → Verify;
//                                                                     MESSAGE/SIGNED → Decrypt(text);
//                                                                     else → Encrypt(text)
//   armored, >32KB                                                → detached-sig → Verify; else Decrypt(file)
//   binary detached signature (packet tag 2)                     → Verify (file)
//   binary: inspectEncryptedMessage finds recipients/SKESK        → Decrypt (file)
//   anything else                                                → Encrypt (file)

package com.pgpony.desktop

import com.pgpony.android.crypto.PGPCryptoService
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.name

/**
 * An operation the caller FORCES — a file-manager context-menu verb, or `pgpony open --op` —
 * instead of letting [DesktopFileRouter.classify] infer one (D14, 2.0.0 plan §2a). The
 * [cliName] spellings get written into Windows registry verbs, `.desktop` Actions and Finder
 * Quick Actions by the installers, so they are a public contract: add names, never rename.
 */
enum class ForcedOp(val cliName: String) {
    ENCRYPT("encrypt"),
    DECRYPT("decrypt"),
    VERIFY("verify"),
    IMPORT("import"),
    RESTORE("restore");

    companion object {
        /** Parse a CLI/wire spelling. Unknown names are null — the caller picks the error. */
        fun fromCli(name: String): ForcedOp? =
            entries.firstOrNull { it.cliName.equals(name.trim(), ignoreCase = true) }
    }
}

/** What opening a file should do. Text variants carry the string; file variants the path. */
sealed class OpenAction {
    data class ImportKey(val armored: String) : OpenAction()
    data class DecryptText(val armored: String) : OpenAction()
    data class EncryptText(val text: String) : OpenAction()
    data class DecryptFile(val path: Path) : OpenAction()
    data class EncryptFile(val path: Path) : OpenAction()
    data class VerifyDetachedSignature(val path: Path) : OpenAction()
    data class RestoreBackup(val path: Path) : OpenAction()
    data object None : OpenAction()
}

object DesktopFileRouter {

    // Same thresholds as Android's IntentHandler (C3): armored ≤32KB prefills a text editor;
    // larger routes to file-mode so the UI never renders a giant string. 1KB head sniff.
    private const val TEXT_PREFILL_LIMIT = 32 * 1024
    private const val HEAD_SNIFF_BYTES = 1024

    private val crypto get() = PGPCryptoService.shared

    /** Classify a file on disk into the action the UI should take. Never throws. */
    fun classify(path: Path): OpenAction = try {
        val bytes = Files.readAllBytes(path)
        if (bytes.isEmpty()) OpenAction.None else classifyBytes(bytes, path)
    } catch (_: Exception) {
        OpenAction.None
    }

    /**
     * [classify] with an optional forced operation (D14). A null [op] is the inference path
     * above; a non-null one takes the decision tree out of the loop entirely — a user who
     * right-clicked "Encrypt" on a `.asc` key file means it, and getting an Import surface
     * instead is the bug this exists to prevent. Never throws.
     *
     * Content is read only where it still chooses BETWEEN variants of the same action (text
     * vs file), never to second-guess the op — and not at all for encrypt/verify/restore, so
     * forcing encrypt on a 10 GB file doesn't buffer it (the 3b rule starts here).
     */
    fun classify(path: Path, op: ForcedOp?): OpenAction {
        if (op == null) return classify(path)
        if (!Files.isRegularFile(path)) return OpenAction.None
        return try {
            val bytes = when (op) {
                ForcedOp.ENCRYPT, ForcedOp.VERIFY, ForcedOp.RESTORE -> EMPTY
                ForcedOp.IMPORT -> Files.readAllBytes(path)
                ForcedOp.DECRYPT ->
                    if (Files.size(path) <= TEXT_PREFILL_LIMIT) Files.readAllBytes(path) else EMPTY
            }
            classifyBytes(bytes, path, op)
        } catch (_: Exception) {
            OpenAction.None
        }
    }

    /**
     * The forced-op core (exposed for tests, which build bytes in memory, like [classifyBytes]).
     * [op] picks the ACTION KIND; [bytes] only choose between its text and file variants.
     */
    fun classifyBytes(bytes: ByteArray, path: Path, op: ForcedOp): OpenAction = when (op) {
        ForcedOp.ENCRYPT -> OpenAction.EncryptFile(path)
        ForcedOp.VERIFY -> OpenAction.VerifyDetachedSignature(path)
        ForcedOp.RESTORE -> OpenAction.RestoreBackup(path)
        // Import consumes armored text; a non-key payload surfaces as the Import screen's own
        // "not a key" error, which names the op the user asked for — better than a silent reroute.
        ForcedOp.IMPORT -> OpenAction.ImportKey(String(bytes, Charsets.UTF_8).trim())
        ForcedOp.DECRYPT -> {
            val text = if (bytes.isNotEmpty() && bytes.size <= TEXT_PREFILL_LIMIT) {
                String(bytes, Charsets.UTF_8).trim()
            } else ""
            if (text.contains("-----BEGIN PGP MESSAGE-----") ||
                text.contains("-----BEGIN PGP SIGNED MESSAGE-----")
            ) {
                OpenAction.DecryptText(text)
            } else {
                OpenAction.DecryptFile(path)
            }
        }
    }

    private val EMPTY = ByteArray(0)

    /** The classification core (exposed for tests, which build bytes in memory). */
    fun classifyBytes(bytes: ByteArray, path: Path): OpenAction {
        if (bytes.isEmpty()) return OpenAction.None
        val filename = path.name
        val head = headText(bytes)

        // Backups open to Restore (before generic message routing).
        if (filename.endsWith(".pgpony", ignoreCase = true) ||
            head.contains("PGPony Backup", ignoreCase = true) ||
            head.contains("Passphrase-Format", ignoreCase = true)   // OpenKeychain numeric9x4
        ) {
            return OpenAction.RestoreBackup(path)
        }

        // An encrypted .eml declares its RFC 3156 envelope in the head; decrypt as a file.
        if (head.contains("multipart/encrypted", ignoreCase = true)) {
            return OpenAction.DecryptFile(path)
        }

        if (head.contains("-----BEGIN PGP")) {
            // Key blocks: import consumes armored text, size-exempt (big keyserver keys).
            if (head.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
                head.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----")
            ) {
                return OpenAction.ImportKey(String(bytes, Charsets.UTF_8).trim())
            }
            if (bytes.size <= TEXT_PREFILL_LIMIT) {
                val text = String(bytes, Charsets.UTF_8).trim()
                if (isDetachedSignature(text)) return OpenAction.VerifyDetachedSignature(path)
                if (text.contains("-----BEGIN PGP MESSAGE-----") ||
                    text.contains("-----BEGIN PGP SIGNED MESSAGE-----")
                ) {
                    return OpenAction.DecryptText(text)
                }
                return OpenAction.EncryptText(text)
            }
            // Large armored content: route by head markers alone.
            if (isDetachedSignature(head)) return OpenAction.VerifyDetachedSignature(path)
            return OpenAction.DecryptFile(path)
        }

        // Binary detached signature (gpg -b without --armor, packet tag 2).
        if (isBinaryDetachedSignature(bytes)) return OpenAction.VerifyDetachedSignature(path)

        // Binary: distinguish a real encrypted OpenPGP message from an arbitrary file by
        // PARSING (many formats have bit 0x80 set), not a first-byte sniff.
        val looksEncrypted = try {
            val info = crypto.inspectEncryptedMessage(bytes)
            info.publicKeyIDs.isNotEmpty() || info.isPasswordEncrypted
        } catch (_: Exception) {
            false
        }
        return if (looksEncrypted) OpenAction.DecryptFile(path) else OpenAction.EncryptFile(path)
    }

    // ── Sniff helpers (mirrors of the Android privates) ─────────────────

    private fun headText(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val n = minOf(bytes.size, HEAD_SNIFF_BYTES)
        return try {
            String(bytes, 0, n, Charsets.UTF_8)
        } catch (_: Exception) {
            ""
        }
    }

    /** A standalone detached signature: a SIGNATURE armor with no SIGNED MESSAGE wrapper. */
    private fun isDetachedSignature(text: String): Boolean =
        text.contains("-----BEGIN PGP SIGNATURE-----") &&
            !text.contains("-----BEGIN PGP SIGNED MESSAGE-----")

    /** Binary detached signature: first packet is an OpenPGP Signature (tag 2), old or new format. */
    private fun isBinaryDetachedSignature(bytes: ByteArray): Boolean {
        if (bytes.isEmpty()) return false
        val b = bytes[0].toInt() and 0xFF
        if (b and 0x80 == 0) return false
        val tag = if (b and 0x40 == 0) (b shr 2) and 0x0F else b and 0x3F
        return tag == 2
    }
}
