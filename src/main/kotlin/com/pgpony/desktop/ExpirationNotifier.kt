// ExpirationNotifier.kt
// PGPony Desktop — D9: key-expiration reminders. The desktop analog of Android's
// notifications/KeyExpirationService (AlarmManager) — the desktop has no OS alarm scheduler, so
// instead of scheduling wake-ups we scan on launch and once a day while running, and post a
// Compose desktop Notification through the tray. Same reminder windows as Android/iOS
// (30 / 7 / 1 / 0 days), plus already-expired. The scan itself is pure and unit-tested; the
// Gui owns the tray plumbing and the once-per-session de-duplication.
//
// D11b — the headline is a WHOLE key with the key's name as an argument, never a name
// concatenated with a phrase. "K 1A2B has EXPIRED" is English word order; German puts the
// verb at the end ("... ist ABGELAUFEN") and splits the day-count phrase around it
// ("laeuft in 5 Tagen ab"), so only a full-sentence key is translatable at all. bucket()
// below is NOT user-facing — it is the de-dup discriminator and stays an ASCII constant.

package com.pgpony.desktop

import com.pgpony.android.data.PGPKeyEntity
import java.util.concurrent.TimeUnit

/** A key that warrants an expiration reminder, with a rendered headline + urgency. */
data class ExpiryReminder(
    val entity: PGPKeyEntity,
    val daysLeft: Long,          // negative when already expired
    val headline: String,
    val urgent: Boolean          // ≤1 day or already expired
) {
    /** Stable de-dup key so a reminder fires once per (key, window) per session. */
    val dedupeKey: String get() = "${entity.fingerprint}@${bucket(daysLeft)}"
}

object ExpirationNotifier {

    /** Reminder windows in days — the Android/iOS set (KeyExpirationService). */
    val REMINDER_DAYS = longArrayOf(30, 7, 1, 0)

    /**
     * Keys that should prompt a reminder at [nowMs]. Only SECRET keys (the ones the user can
     * actually renew) with a set expiry, not already revoked. A key reports at the tightest
     * window it has entered: an already-expired key, or one within 0/1/7/30 days. Keys further
     * out than 30 days are silent.
     */
    fun due(keys: List<PGPKeyEntity>, nowMs: Long): List<ExpiryReminder> =
        keys.mapNotNull { key ->
            if (!key.isKeyPair || key.isRevoked) return@mapNotNull null
            val expiresAt = key.expiresAt ?: return@mapNotNull null
            val msLeft = expiresAt - nowMs
            val daysLeft = msLeft.floorDivDays()
            val who = key.userID.ifBlank { key.shortFingerprint }
            // The 7- and 30-day windows read the same sentence. They remain distinct reminders
            // because bucket() discriminates them for de-dup, not because the copy differs, so
            // they collapse into one branch rather than two identical ones.
            when {
                msLeft <= 0 -> reminder(key, daysLeft, tr("d_expiry_headline_expired", who), urgent = true)
                daysLeft <= 0L -> reminder(key, 0, tr("d_expiry_headline_today", who), urgent = true)
                daysLeft <= 1L -> reminder(key, 1, tr("d_expiry_headline_tomorrow", who), urgent = true)
                daysLeft <= 30L ->
                    reminder(key, daysLeft, trQuantity("d_expiry_headline_days", daysLeft.toInt(), who), urgent = false)
                else -> null
            }
        }

    private fun reminder(key: PGPKeyEntity, daysLeft: Long, headline: String, urgent: Boolean) =
        ExpiryReminder(entity = key, daysLeft = daysLeft, headline = headline, urgent = urgent)

    private fun Long.floorDivDays(): Long = Math.floorDiv(this, TimeUnit.DAYS.toMillis(1))
}

/** The window bucket a day-count falls in, for de-dup. File-level so ExpiryReminder can use it. */
internal fun bucket(daysLeft: Long): String = when {
    daysLeft < 0 -> "expired"
    daysLeft <= 0 -> "0"
    daysLeft <= 1 -> "1"
    daysLeft <= 7 -> "7"
    else -> "30"
}
