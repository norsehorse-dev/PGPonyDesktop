// AppWipe.kt
// PGPony Android 4.7.0 (item 32): the wipe behind the duress PIN and the
// optional wrong-PIN limit.
//
// Silent by design: no prompt, no progress, no message. The lock screen keeps
// showing its ordinary "checking" state while this runs, then the app comes
// back as a fresh install on onboarding.
//
// Order:
//   1. WipeFlag.markPending (filesDir/wipe_pending, synced) before anything else:
//      AppLock.submit writes it under its lock before the outcome leaves, and
//      wipe() writes it again. A failed write never holds the wipe back.
//   2. SecureKeyStore.cryptoErase: the Keystore keys (pgpony_keystore_v2_hw and
//      the legacy androidx master key) and every DEK envelope, so the secret
//      material is unreadable even if the rest is cut short.
//   3. AppReset.resetAll, the same complete reset as Clear All Data (in its
//      WIPE mode, which leaves the screen alone), then the app language.
//   4. The :remote_api process is killed, so no passphrase or plaintext it
//      held in memory survives.
//   5. The flag is removed, after a full pass whatever single step failed (a
//      flag left behind would wipe the next fresh setup).
//   6. A new MainActivity task, and this process ends, so nothing decrypted
//      before the lock survives in a ViewModel either.
// A main-process start that finds the flag (the process was killed mid-wipe)
// runs 2, 3 and 5 again before any screen opens (resumeIfPending, from
// PGPonyApp.onCreate). A :remote_api start that finds it only drops its own
// in-memory secrets and its service, and leaves the flag to the main process.

package com.pgpony.android.lock

import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import com.pgpony.android.PGPonyApp
import com.pgpony.android.data.AppReset
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

object AppWipe {

    private fun flag(context: Context) = WipeFlag(context.applicationContext.filesDir)

    /** Steps 1 to 5. Not cancellable once started. */
    suspend fun wipe(context: Context) {
        val app = context.applicationContext
        withContext(NonCancellable + Dispatchers.IO) {
            runCatching { flag(app).markPending() }
            runCatching { PGPonyApp.instance.secureKeyStore.cryptoErase() }
            runCatching { AppReset.resetAll(app, AppReset.Mode.WIPE) }
            runCatching { killProviderProcess(app) }
            withContext(Dispatchers.Main) { AppReset.resetAppLocale() }
            runCatching { flag(app).clear() }
        }
    }

    /**
     * Wipe, then reopen as a fresh install. Runs on the process scope, so a lock
     * screen that leaves composition mid-wipe (a rotation, say) does not stop it.
     */
    fun wipeAndRestart(context: Context, activity: Activity?) {
        val app = context.applicationContext
        PGPonyApp.instance.applicationScope.launch {
            wipe(app)
            withContext(Dispatchers.Main) { restartFresh(app, activity) }
        }
    }

    private fun restartFresh(app: Context, activity: Activity?) {
        // The Quick Action has its own task; close it so Recents does not keep it.
        if (activity != null && activity !is com.pgpony.android.MainActivity) {
            runCatching { activity.finishAndRemoveTask() }
        }
        runCatching {
            app.startActivity(
                Intent(app, com.pgpony.android.MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            )
        }
        android.os.Process.killProcess(android.os.Process.myPid())
    }

    private fun killProviderProcess(app: Context) {
        val am = app.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return
        val name = "${app.packageName}:remote_api"
        val myPid = android.os.Process.myPid()
        am.runningAppProcesses?.forEach { p ->
            if (p.processName == name && p.pid != myPid) android.os.Process.killProcess(p.pid)
        }
    }

    /**
     * Finish a wipe the system cut short. Called from PGPonyApp.onCreate in every
     * process, before the first screen or provider call. Only the main process
     * redoes the persistent reset and removes the flag; :remote_api drops its
     * in-memory secrets and stops its service, so a provider restarted mid-wipe
     * cannot run a reset over the user's fresh setup.
     */
    fun resumeIfPending(context: Context, mainProcess: Boolean) {
        val app = context.applicationContext
        val f = flag(app)
        if (!f.isPending()) return
        if (!mainProcess) {
            AppReset.clearProcessSecrets(app)
            return
        }
        runBlocking(Dispatchers.IO) {
            runCatching { PGPonyApp.instance.secureKeyStore.cryptoErase() }
            runCatching { AppReset.resetAll(app, AppReset.Mode.WIPE) }
        }
        // On the main thread already (Application.onCreate), before
        // LanguageState reads it.
        AppReset.resetAppLocale()
        runCatching { f.clear() }
    }
}
