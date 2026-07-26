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
 * The open-file bus. The UI registers [handler]; everything else calls [deliver]. Paths that
 * arrive before a handler is set queue in [pending] and are drained on registration, so a file
 * passed on the very first launch still routes once the window exists.
 */
object AppOpen {
    private val lock = Any()
    private var handler: ((List<Path>) -> Unit)? = null
    private val pending = mutableListOf<Path>()

    /** Called by DesktopState once it can route. Drains anything queued so far. */
    fun setHandler(h: (List<Path>) -> Unit) {
        val drain: List<Path>
        synchronized(lock) {
            handler = h
            drain = pending.toList()
            pending.clear()
        }
        if (drain.isNotEmpty()) h(drain)
    }

    /** Deliver files to the UI (or queue them until a handler exists). */
    fun deliver(paths: List<Path>) {
        val existing: ((List<Path>) -> Unit)?
        synchronized(lock) {
            existing = handler
            if (existing == null) pending.addAll(paths)
        }
        existing?.invoke(paths)
    }

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
     * the primary begins serving forwarded opens. On failure the [files] are forwarded to the
     * already-running instance and this returns false (the caller should exit).
     *
     * If anything about the IPC goes wrong (stale port file, refused connection), we fail SAFE
     * by treating this process as primary — a second window beats a file that opens nothing.
     */
    fun acquire(files: List<Path>): Boolean {
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
            if (files.isNotEmpty()) AppOpen.deliver(files)
            Runtime.getRuntime().addShutdownHook(Thread {
                runCatching { Files.deleteIfExists(portPath) }
            })
            return true
        }

        // Secondary: forward our files to the primary and bow out.
        channel.close()
        if (files.isEmpty()) {
            // A bare second launch with no file: just raise the primary if we can, then exit.
            forward(portPath, emptyList())
            return false
        }
        val ok = forward(portPath, files)
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
            val paths = mutableListOf<Path>()
            runCatching {
                BufferedReader(InputStreamReader(s.getInputStream(), Charsets.UTF_8)).use { reader ->
                    reader.lineSequence().forEach { line ->
                        val trimmed = line.trim()
                        if (trimmed.isNotEmpty()) {
                            runCatching { Path.of(trimmed) }.getOrNull()?.let { paths.add(it) }
                        }
                    }
                }
            }
            // Always raise the window on a forwarded launch, even a bare one.
            AppOpen.focusWindow?.invoke()
            if (paths.isNotEmpty()) AppOpen.deliver(paths)
        }
    }

    private fun forward(portPath: Path, files: List<Path>): Boolean {
        val port = runCatching { Files.readString(portPath).trim().toInt() }.getOrNull() ?: return false
        return try {
            Socket(InetAddress.getLoopbackAddress(), port).use { socket ->
                OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8).use { w ->
                    files.forEach { w.write(it.toAbsolutePath().toString() + "\n") }
                    w.flush()
                }
            }
            true
        } catch (_: Exception) {
            false
        }
    }
}
