// PortablePreferences.kt
// PGPony Desktop 3.1.0 (plan 3e.2): settings on the drive in portable mode.
//
// The app reads and writes its settings through java.util.prefs from 16 places. The JDK stores
// that tree in the Windows registry, a macOS plist or ~/.java, all on the host. In portable mode
// PortableMode.apply() names this factory in java.util.prefs.PreferencesFactory before the JDK's
// Preferences class loads, so every one of those call sites lands in one properties file in the
// data folder instead, and none of them changes.
//
// The file holds one entry per value, keyed by the node's absolute path and the key joined with
// a tab ("/app/pgpony/desktop<TAB>ui_language"); a tab cannot appear in a node name or key the app
// uses. It is rewritten whole on flush through a temp file and a move, so a crash or a pulled
// drive leaves the old file or the new one, never half of each. A shutdown hook flushes too.
//
// The system root is the same tree: the app never uses it, and a portable copy must not reach
// the host's system store either.

package com.pgpony.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.Properties
import java.util.prefs.AbstractPreferences
import java.util.prefs.Preferences
import java.util.prefs.PreferencesFactory

class PortablePreferencesFactory : PreferencesFactory {
    override fun userRoot(): Preferences = root
    override fun systemRoot(): Preferences = root

    companion object {
        private val root: Preferences by lazy {
            val file = System.getProperty(PortableMode.SETTINGS_PROPERTY)
                ?: error("${PortableMode.SETTINGS_PROPERTY} is not set")
            FilePreferences.root(Path.of(file))
        }
    }
}

/** A preferences tree kept in one properties file. */
class FilePreferences private constructor(
    parent: FilePreferences?,
    name: String,
    private val store: Store
) : AbstractPreferences(parent, name) {

    /** The file and its contents, shared by every node of one tree. */
    class Store(val file: Path) {
        val values = sortedMapOf<String, String>()
        /** Node paths that exist, including nodes with no values yet. */
        val nodes = sortedSetOf("/")
        var dirty = false

        init {
            if (Files.isRegularFile(file)) {
                val p = Properties()
                Files.newInputStream(file).use { p.load(it) }
                for (k in p.stringPropertyNames()) {
                    val tab = k.indexOf('\t')
                    if (tab < 0) {
                        if (k.startsWith("/")) nodes += k
                        continue
                    }
                    val node = k.substring(0, tab)
                    values[k] = p.getProperty(k)
                    addNodeWithParents(node)
                }
            }
        }

        fun addNodeWithParents(node: String) {
            var n = node
            while (true) {
                nodes += n
                if (n == "/") break
                n = n.substringBeforeLast('/').ifEmpty { "/" }
            }
        }

        @Synchronized
        fun save() {
            if (!dirty) return
            val p = Properties()
            for ((k, v) in values) p.setProperty(k, v)
            // Empty nodes are kept too, so a node created and left empty still exists next time.
            for (n in nodes) if (values.keys.none { it.startsWith("$n\t") }) p.setProperty(n, "")
            file.parent?.let { Files.createDirectories(it) }
            val tmp = file.resolveSibling(file.fileName.toString() + ".tmp")
            Files.newOutputStream(tmp).use { p.store(it, "PGPony settings (portable)") }
            try {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING)
            }
            dirty = false
        }
    }

    private val nodePath: String get() = absolutePath()

    private fun key(k: String) = "$nodePath\t$k"

    override fun putSpi(key: String, value: String) = synchronized(store) {
        store.addNodeWithParents(nodePath)
        store.values[key(key)] = value
        store.dirty = true
    }

    override fun getSpi(key: String): String? = synchronized(store) { store.values[key(key)] }

    override fun removeSpi(key: String) {
        synchronized(store) { if (store.values.remove(key(key)) != null) store.dirty = true }
    }

    override fun removeNodeSpi() {
        synchronized(store) {
            val prefix = "$nodePath/"
            store.values.keys.removeIf { it.startsWith("$nodePath\t") || it.startsWith(prefix) }
            store.nodes.removeIf { it == nodePath || it.startsWith(prefix) }
            store.dirty = true
        }
    }

    override fun keysSpi(): Array<String> = synchronized(store) {
        val prefix = "$nodePath\t"
        store.values.keys.filter { it.startsWith(prefix) }.map { it.removePrefix(prefix) }.toTypedArray()
    }

    override fun childrenNamesSpi(): Array<String> = synchronized(store) {
        val prefix = if (nodePath == "/") "/" else "$nodePath/"
        store.nodes.asSequence()
            .filter { it != nodePath && it.startsWith(prefix) }
            .map { it.removePrefix(prefix).substringBefore('/') }
            .filter { it.isNotEmpty() }
            .distinct().toList().toTypedArray()
    }

    override fun childSpi(name: String): AbstractPreferences {
        val child = FilePreferences(this, name, store)
        synchronized(store) {
            if (child.nodePath !in store.nodes) {
                store.addNodeWithParents(child.nodePath)
                store.dirty = true
            }
        }
        return child
    }

    override fun syncSpi() = store.save()

    override fun flushSpi() = store.save()

    override fun flush() {
        super.flush()
        store.save()
    }

    companion object {
        fun root(file: Path): FilePreferences {
            val store = Store(file)
            Runtime.getRuntime().addShutdownHook(Thread({ runCatching { store.save() } }, "pgpony-prefs-flush"))
            return FilePreferences(null, "", store)
        }
    }
}
