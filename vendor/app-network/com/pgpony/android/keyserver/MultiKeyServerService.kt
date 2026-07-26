// MultiKeyServerService.kt
// PGPony Android — 4.0.0 Phase 5a
//
// Per-server VKS operations for the multi-keyserver model: fetch,
// upload, and verification-status polling against an arbitrary
// KeyServer.baseUrl. The shipped KeyServerRepository stays the
// single-server (keys.openpgp.org) path for the existing refresh /
// exchange / contacts callers — this class is the additive multi-server
// layer PublishSheet and the (future) Phase 5 batch refresh use, so the
// blast radius on shipped code is zero. (Plan said "modify
// KeyServerRepository"; a focused new service is the lower-risk shape
// and keeps the existing single-server contract intact.)
//
// All three seed/servers speak the keys.openpgp.org VKS dialect
// (keys.pgpony.app implements the same API by design), so one client
// path covers them. HKP POST /pks/add is the fallback upload verb if a
// server lacks /vks/v1/upload (Open Question 5); VKS is preferred and
// tried first.

package com.pgpony.android.keyserver

import com.pgpony.android.PGPonyApp
import com.pgpony.android.network.HttpClientFactory
import com.pgpony.android.network.ProxyPrefs
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.client.request.forms.FormDataContent
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.contentType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** Outcome of publishing one key to one server. */
sealed class PublishOutcome {
    /** Uploaded; verification emails requested for [pendingEmails] (may be empty). */
    data class Ok(val pendingEmails: List<String>) : PublishOutcome()
    /** The server refused the key — very likely a key-type it doesn't accept (R5). */
    data class RejectedKeyType(val httpStatus: Int) : PublishOutcome()
    /** Any other failure (network, 5xx, malformed). [message] is user-safe. */
    data class Failed(val message: String) : PublishOutcome()
}

class MultiKeyServerService {

    companion object {
        val shared = MultiKeyServerService()
    }

    // Phase 6: the shared proxy-aware client (Tor/Orbot when enabled).
    private val client get() = HttpClientFactory.client()

    // Phase 6: rewrite keys.pgpony.app → its onion when a proxy + the
    // onion mirror are active; clearnet otherwise.
    private fun base(server: KeyServer): String =
        ProxyPrefs.effectiveBaseUrl(PGPonyApp.instance, server.baseUrl)

    /**
     * Fetch a key's armored material by fingerprint from one server.
     * Returns the armor on 200, null on 404 (not published), THROWS on
     * transport failure so the caller can tell "not there" from
     * "couldn't reach it" (matches KeyServerRepository.fetchByFingerprint).
     */
    suspend fun fetchByFingerprint(server: KeyServer, fingerprint: String): String? =
        withContext(Dispatchers.IO) {
            val fp = fingerprint.uppercase().replace(" ", "")
            val response = client.get("${base(server)}/vks/v1/by-fingerprint/$fp") {
                accept(ContentType.Application.OctetStream)
            }
            if (response.status == HttpStatusCode.OK) response.bodyAsText() else null
        }

    /**
     * Fetch a key's armored material by EMAIL from one server's VKS
     * by-email endpoint. Returns the armor on 200, null on any other
     * status (Hagrid/VKS 404s addresses it hasn't verified), THROWS on
     * transport failure so the caller can distinguish "not there" from
     * "couldn't reach it". Mirrors [fetchByFingerprint].
     *
     * Phase 6: used by KeyServerRepository.findByEmail to search the
     * configured directory (keys.pgpony.app first) before falling back
     * to keys.openpgp.org — so v6 keys that live only on the first-party
     * server are found, and the lookup rides the onion when Tor is on.
     */
    suspend fun searchByEmail(server: KeyServer, email: String): String? =
        withContext(Dispatchers.IO) {
            val response = client.get("${base(server)}/vks/v1/by-email/${email.trim()}") {
                accept(ContentType.Application.OctetStream)
            }
            if (response.status == HttpStatusCode.OK) response.bodyAsText() else null
        }

    /**
     * Query [servers] (already filtered to lookupEnabled, in order) and
     * return the FIRST armored hit. Merge across servers is the caller's
     * job (the import layer merges by fingerprint), so this just returns
     * the first non-null; callers wanting every server's copy can map
     * over [fetchByFingerprint] instead.
     */
    suspend fun lookupInOrderByFingerprint(
        servers: List<KeyServer>,
        fingerprint: String
    ): String? {
        for (server in servers) {
            val hit = runCatching { fetchByFingerprint(server, fingerprint) }.getOrNull()
            if (!hit.isNullOrBlank()) return hit
        }
        return null
    }

    /**
     * Publish [armoredPublicKey] to one server. Tries VKS
     * /vks/v1/upload (+ auto request-verify for unpublished emails);
     * falls back to HKP POST /pks/add if VKS isn't available. A 4xx that
     * looks like a key-type rejection returns [PublishOutcome.RejectedKeyType]
     * so the sheet can show the R5 "not accepted — key type" copy
     * instead of a raw HTTP error.
     */
    suspend fun publish(server: KeyServer, armoredPublicKey: String): PublishOutcome =
        withContext(Dispatchers.IO) {
            try {
                val vks = tryVksUpload(server, armoredPublicKey)
                if (vks != null) return@withContext vks
                // VKS not available (404 on the endpoint) → HKP add.
                tryHkpAdd(server, armoredPublicKey)
            } catch (e: Exception) {
                PublishOutcome.Failed(e.message ?: "Upload failed")
            }
        }

    /** @return null if the server has no /vks/v1/upload (caller falls back to HKP). */
    private suspend fun tryVksUpload(server: KeyServer, armored: String): PublishOutcome? {
        val response = client.post("${base(server)}/vks/v1/upload") {
            contentType(ContentType.Application.Json)
            setBody(JSONObject().put("keytext", armored).toString())
        }
        return when (response.status) {
            HttpStatusCode.OK -> {
                val json = JSONObject(response.bodyAsText())
                val token = json.optString("token", "")
                val statusObj = json.optJSONObject("status")
                val unpublished = mutableListOf<String>()
                if (statusObj != null) {
                    val it = statusObj.keys()
                    while (it.hasNext()) {
                        val email = it.next()
                        if (statusObj.optString(email, "") == "unpublished") unpublished += email
                    }
                }
                if (token.isNotEmpty() && unpublished.isNotEmpty()) {
                    runCatching { requestVerify(server, token, unpublished) }
                }
                PublishOutcome.Ok(pendingEmails = unpublished)
            }
            HttpStatusCode.NotFound -> null // no VKS upload endpoint here
            HttpStatusCode.BadRequest,
            HttpStatusCode.UnsupportedMediaType,
            HttpStatusCode.UnprocessableEntity ->
                PublishOutcome.RejectedKeyType(response.status.value)
            else -> PublishOutcome.Failed("HTTP ${response.status.value}")
        }
    }

    private suspend fun tryHkpAdd(server: KeyServer, armored: String): PublishOutcome {
        val response = client.post("${base(server)}/pks/add") {
            setBody(FormDataContent(Parameters.build { append("keytext", armored) }))
        }
        return when {
            response.status == HttpStatusCode.OK -> PublishOutcome.Ok(pendingEmails = emptyList())
            response.status.value in 400..499 ->
                PublishOutcome.RejectedKeyType(response.status.value)
            else -> PublishOutcome.Failed("HTTP ${response.status.value}")
        }
    }

    private suspend fun requestVerify(server: KeyServer, token: String, emails: List<String>) {
        client.post("${base(server)}/vks/v1/request-verify") {
            contentType(ContentType.Application.Json)
            setBody(
                JSONObject().apply {
                    put("token", token)
                    put("addresses", JSONArray(emails))
                }.toString()
            )
        }
    }

    /**
     * Verification status for (key, server): fetch the server's copy by
     * fingerprint and check whether it carries [expectedEmail] as a
     * user id. Hagrid/VKS suppress email UIDs until the owner confirms,
     * so a served key WITH the UID means "✓ verified identity"; served
     * WITHOUT it means "published, awaiting email verification"; not
     * served at all → NotPublished.
     */
    suspend fun verificationStatus(
        server: KeyServer,
        fingerprint: String,
        expectedEmail: String?
    ): VerificationStatus = withContext(Dispatchers.IO) {
        val armored = runCatching { fetchByFingerprint(server, fingerprint) }.getOrElse {
            return@withContext VerificationStatus.Unknown
        } ?: return@withContext VerificationStatus.NotPublished
        if (expectedEmail.isNullOrBlank()) return@withContext VerificationStatus.Published
        if (armored.contains(expectedEmail, ignoreCase = true)) {
            VerificationStatus.VerifiedIdentity
        } else {
            VerificationStatus.AwaitingEmailVerification
        }
    }
}

enum class VerificationStatus {
    Unknown,
    NotPublished,
    Published,                 // served, no email UID expected/checked
    AwaitingEmailVerification, // served by fingerprint, UID not yet confirmed
    VerifiedIdentity           // served WITH the confirmed email UID
}
