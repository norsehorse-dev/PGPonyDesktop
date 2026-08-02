// SingleInstance.kt
// PGPony Desktop — D9: single-instance behavior + the open-file bus.
//
// A second launch (double-clicking another .asc while PGPony is already open) must not spin up
// a second window — it should hand its file to the RUNNING instance and bring that window
// forward. The Android/iOS single-task model is implicit; on the desktop we build it:
//
//   • The FIRST process to acquire an exclusive lock on dataDir/.instance.lock is the PRIMARY.
//     It opens a loopback ServerSocket, writes the chosen port to dataDir/.instance.port, and
//     serves newline-delimited file paths to AppOpen.
//   • A later process can't take the lock → it's a SECONDARY. It reads the port, connects,
//     sends its file arguments, and exits. Nothing is drawn twice.
//
// AppOpen is the bus in between: the initial CLI file args, macOS "Open With" events, and
// forwarded paths from secondaries all funnel through it; DesktopState registers a handler and
// drains anything that queued before the UI was ready.

package com.pgpony.desktop

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/**
 * One delivery on the open-file bus: the paths, plus the operation the caller forced, if any
 * (D14 — `pgpony open --op`, and the context-menu verbs built on it).
 */
data class OpenRequest(val paths: List<Path>, val op: ForcedOp? = null)

/**
 * The open-file bus. The UI registers [handler]; everything else calls [deliver]. Requests that
 * arrive before a handler is set queue in [pending] and are drained on registration, so a file
 * passed on the very first launch still routes once the window exists. Queued as REQUESTS, not
 * pooled paths — two forwarded opens with different forced ops must not merge into one batch
 * that could only keep a single op.
 */
object AppOpen {
    private val lock = Any()
    private var handler: ((OpenRequest) -> Unit)? = null
    private val pending = mutableListOf<OpenRequest>()

    /** Called by DesktopState once it can route. Drains anything queued so far, in order. */
    fun setHandler(h: (OpenRequest) -> Unit) {
        val drain: List<OpenRequest>
        synchronized(lock) {
            handler = h
            drain = pending.toList()
            pending.clear()
        }
        drain.forEach(h)
    }

    /** Deliver a request to the UI (or queue it until a handler exists). */
    fun deliver(request: OpenRequest) {
        if (request.paths.isEmpty()) return
        val existing: ((OpenRequest) -> Unit)?
        synchronized(lock) {
            existing = handler
            if (existing == null) pending.add(request)
        }
        existing?.invoke(request)
    }

    /** The un-forced shape most callers mean (drag-drop, macOS open events). */
    fun deliver(paths: List<Path>) = deliver(OpenRequest(paths))

    /** Optional window-focus hook set by the GUI so a forwarded open raises the window. */
    @Volatile var focusWindow: (() -> Unit)? = null
}

object SingleInstance {

    private const val LOCK_FILE = ".instance.lock"
    private const val PORT_FILE = ".instance.port"

    // Held for the process lifetime so the OS keeps the lock; never released explicitly.
    private var lockChannel: FileChannel? = null
    private var lock: FileLock? = null

    /**
     * Try to become the primary instance. On success returns true (the caller opens the GUI);
     * the primary begins serving forwarded opens. On failure the [request] is forwarded to the
     * already-running instance and this returns false (the caller should exit).
     *
     * If anything about the IPC goes wrong (stale port file, refused connection), we fail SAFE
     * by treating this process as primary — a second window beats a file that opens nothing.
     */
    fun acquire(request: OpenRequest): Boolean {
        val files = request.paths
        val lockPath = Config.dataDir.resolve(LOCK_FILE)
        val portPath = Config.dataDir.resolve(PORT_FILE)

        val channel = FileChannel.open(
            lockPath,
            StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE
        )
        val acquired = try {
            channel.tryLock()
        } catch (_: Exception) {
            null // lock already held by another process (OverlappingFileLockException etc.)
        }

        if (acquired != null) {
            // We're primary. Keep the lock, start the forwarding server.
            lockChannel = channel
            lock = acquired
            startServer(portPath)
            if (files.isNotEmpty()) AppOpen.deliver(request)
            Runtime.getRuntime().addShutdownHook(Thread {
                runCatching { Files.deleteIfExists(portPath) }
            })
            return true
        }

        // Secondary: forward our request to the primary and bow out.
        channel.close()
        if (files.isEmpty()) {
            // A bare second launch with no file: just raise the primary if we can, then exit.
            forward(portPath, OpenRequest(emptyList()))
            return false
        }
        val ok = forward(portPath, request)
        if (!ok) {
            // Couldn't reach the primary (stale state). Fail safe: run as our own instance.
            return true
        }
        return false
    }

    private fun startServer(portPath: Path) {
        val server = ServerSocket(0, 4, InetAddress.getLoopbackAddress())
        Files.writeString(portPath, server.localPort.toString())
        val t = Thread {
            while (!server.isClosed) {
                val socket = try {
                    server.accept()
                } catch (_: Exception) {
                    break
                }
                handleConnection(socket)
            }
        }
        t.isDaemon = true
        t.name = "pgpony-single-instance"
        t.start()
    }

    private fun handleConnection(socket: Socket) {
        socket.use { s ->
            var request = OpenRequest(emptyList())
            runCatching {
                BufferedReader(InputStreamReader(s.getInputStream(), Charsets.UTF_8)).use { reader ->
                    request = parseForwarded(reader.lineSequence())
                }
            }
            // Always raise the window on a forwarded launch, even a bare one.
            AppOpen.focusWindow?.invoke()
            if (request.paths.isNotEmpty()) AppOpen.deliver(request)
        }
    }

    /**
     * The wire format, reading side (exposed for tests). One optional header line
     * `--op <name>`, then one absolute path per line. No collision is possible: [forward]
     * writes absolute paths, and an absolute path never begins with `--`. An unknown op name
     * (a newer secondary talking to an older primary) degrades to classification rather than
     * dropping the files.
     */
    internal fun parseForwarded(lines: Sequence<String>): OpenRequest {
        var op: ForcedOp? = null
        val paths = mutableListOf<Path>()
        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            if (trimmed.startsWith(OP_HEADER)) {
                op = ForcedOp.fromCli(trimmed.removePrefix(OP_HEADER))
                continue
            }
            runCatching { Path.of(trimmed) }.getOrNull()?.let { paths.add(it) }
        }
        return OpenRequest(paths, op)
    }

    private const val OP_HEADER = "--op "

    private fun forward(portPath: Path, request: OpenRequest): Boolean {
        val port = runCatching { Files.readString(portPath).trim().toInt() }.getOrNull() ?: return false
        return try {
            Socket(InetAddress.getLoopbackAddress(), port).use { socket ->
                OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8).use { w ->
                    request.op?.let { w.write(OP_HEADER + it.cliName + "\n") }
                    request.paths.forEach { w.write(it.toAbsolutePath().toString() + "\n") }
                    w.flush()
                }
            }
            true
        } catch (_: Exception) {
            false
        }
    }
}
