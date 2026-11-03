// AppLock.kt
// PGPony Android 4.7.0 (item 32): the Android side of the PGPony PIN lock.
//
// AppLockCore does the hashing and the counting; this object keeps its config
// in filesDir/app_lock (AppLockFileStore), runs every hash off the main thread
// and serializes attempts so two quick submits cannot race the counter. The
// lock is on when PIN mode is on (its marker or config exists) or the
// device-unlock lock ("biometric_lock") is on; LockScreen picks the PIN screen
// in PIN mode, and in PIN mode there is never a device-credential way in.

package com.pgpony.android.lock

import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import androidx.compose.runtime.mutableIntStateOf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

object AppLock {

    private const val TAG = "AppLock"

    private val core = AppLockCore(Argon2PinHasher)
    private val mutex = Mutex()

    /**
     * Counts every time the app locks (MainActivity's ON_STOP re-lock). Settings
     * keys its one-per-visit PIN check on it, so a lock always asks again.
     */
    val lockEpoch = mutableIntStateOf(0)

    fun noteLocked() {
        lockEpoch.intValue = lockEpoch.intValue + 1
    }

    private fun store(context: Context) = AppLockFileStore(context.applicationContext.filesDir)

    /** The delay's clock: time since boot and this boot's count. */
    fun clock(context: Context): LockClock {
        val boot: String? = try {
            val n = Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, -1)
            if (n >= 0) n.toString() else null
        } catch (_: Exception) {
            null
        }
        return LockClock(SystemClock.elapsedRealtime(), boot)
    }

    /** PIN mode is on (marker or config). File stats, cheap enough for the main thread. */
    fun isPinSet(context: Context): Boolean = store(context).isOn()

    /** Any app lock: the PGPony PIN, or device unlock. */
    fun isEnabled(context: Context): Boolean =
        isPinSet(context) ||
            context.getSharedPreferences("pgpony_prefs", Context.MODE_PRIVATE).getBoolean("biometric_lock", false)

    suspend fun load(context: Context): AppLockConfig? = withContext(Dispatchers.IO) { store(context).load() }

    fun throttleRemainingMs(context: Context, config: AppLockConfig): Long =
        core.throttleRemainingMs(config, clock(context))

    /**
     * One PIN attempt, persisted before the outcome is returned. Never logs the
     * PIN. For the duress PIN and the wipe limit, the wipe's resume flag is
     * written here, under the lock, before the outcome leaves; a failed write
     * does not hold the wipe back. A wrong PIN that cannot be counted throws
     * (the caller shows it as an error, never as an unlock).
     */
    suspend fun submit(context: Context, pin: String): PinCheck = mutex.withLock {
        val app = context.applicationContext
        val s = store(app)
        val config = withContext(Dispatchers.IO) { s.load() } ?: return@withLock PinCheck.Unsupported
        val now = clock(app)
        val result = withContext(Dispatchers.Default) { core.check(config, pin, now) }
        val outcome = result.outcome
        val updated = result.updated
        when (outcome) {
            PinCheck.Duress, is PinCheck.WipeLimit -> withContext(Dispatchers.IO) {
                if (runCatching { WipeFlag(app.filesDir).markPending() }.isFailure) {
                    Log.w(TAG, "Wipe flag not written; wiping anyway")
                }
                if (updated != null) runCatching { s.save(updated) }
            }
            // The owner is in; a counter that fails to reset must not lock them out.
            PinCheck.Unlocked -> if (updated != null) withContext(Dispatchers.IO) { runCatching { s.save(updated) } }
            else -> if (updated != null) withContext(Dispatchers.IO) { s.save(updated) }
        }
        outcome
    }

    private suspend fun saveIfDone(context: Context, setup: PinSetup): PinSetup {
        if (setup is PinSetup.Done) withContext(Dispatchers.IO) { store(context).save(setup.config) }
        return setup
    }

    /**
     * A new PIN. The PIN-mode marker is written before the config. With
     * [fingerprintAllowed], the fingerprint key is created first; when it
     * cannot be (no strong biometric enrolled), the PIN is set without it.
     */
    suspend fun create(context: Context, pin: String, fingerprintAllowed: Boolean): PinSetup = mutex.withLock {
        val fingerprint = fingerprintAllowed && withContext(Dispatchers.IO) { AppLockBiometricKey.create() }
        val setup = withContext(Dispatchers.Default) { core.create(pin, fingerprint) }
        if (setup is PinSetup.Done) {
            withContext(Dispatchers.IO) { store(context).markOn() }
        } else if (fingerprint) {
            withContext(Dispatchers.IO) { AppLockBiometricKey.delete() }
        }
        saveIfDone(context, setup)
    }

    suspend fun changePin(context: Context, newPin: String): PinSetup = mutex.withLock {
        val config = withContext(Dispatchers.IO) { store(context).load() }
        if (config == null) {
            PinSetup.Unsupported
        } else {
            val setup = withContext(Dispatchers.Default) { core.changePin(config, newPin) }
            saveIfDone(context, setup)
        }
    }

    suspend fun setDuress(context: Context, duressPin: String): PinSetup = mutex.withLock {
        val config = withContext(Dispatchers.IO) { store(context).load() }
        if (config == null) {
            PinSetup.Unsupported
        } else {
            val setup = withContext(Dispatchers.Default) { core.setDuress(config, duressPin) }
            saveIfDone(context, setup)
        }
    }

    private suspend fun update(context: Context, transform: (AppLockConfig) -> AppLockConfig?) {
        mutex.withLock {
            withContext(Dispatchers.IO) {
                val s = store(context)
                val config = s.load()
                if (config != null) {
                    val next = transform(config)
                    if (next != null) s.save(next)
                }
            }
        }
    }

    suspend fun removeDuress(context: Context) = update(context) { core.removeDuress(it) }

    /**
     * Fingerprint on (a fresh Keystore key bound to the enrolled fingerprints)
     * or off (the key deleted). Returns false when turning it on failed.
     */
    suspend fun setFingerprintAllowed(context: Context, allowed: Boolean): Boolean {
        if (allowed) {
            val ok = withContext(Dispatchers.IO) { AppLockBiometricKey.create() }
            if (!ok) return false
        } else {
            withContext(Dispatchers.IO) { AppLockBiometricKey.delete() }
        }
        update(context) { it.copy(fingerprintAllowed = allowed) }
        return true
    }

    suspend fun setWipeAfter(context: Context, wipeAfter: Int) =
        update(context) { core.withWipeAfter(it, wipeAfter) }

    /** Unlocked by fingerprint: the owner is back, so the wrong-PIN count starts over. */
    suspend fun onBiometricUnlock(context: Context) = update(context) { core.resetAttempts(it) }

    /** Leave PIN mode: the PIN, its duress PIN, its counters and the fingerprint key. */
    fun clear(context: Context) {
        store(context).clear()
        AppLockBiometricKey.delete()
    }
}
