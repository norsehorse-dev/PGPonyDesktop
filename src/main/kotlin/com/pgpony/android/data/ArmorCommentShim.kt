// ArmorCommentShim.kt
// PGPony Desktop — D1 vendor shim.
//
// The vendored crypto layer (PGPCryptoService, SigningService, CardSigningService) reads the
// armor "Comment:" header from com.pgpony.android.data.ArmorCommentHeader, whose Android home
// (data/ArmorCommentSettings.kt) couples it to DataStore + Context. This shim reproduces the two
// process-wide objects the crypto layer actually consumes, with the same defaults and the same
// @Volatile read semantics.
//
// SUPERSEDED BY: the D2+ Settings port of ArmorCommentSettings (armor-comment toggle + custom
// text). When that lands, this file is where the desktop store wires its writes — or, better,
// the Android file gets its settable cache split upstream and this shim is deleted in favor of
// vendoring that split file. Until then the defaults match Android's out-of-box behavior
// (comment ON, "PGPony - PGPony.app").

package com.pgpony.android.data

object ArmorCommentDefaults {
    /** Default Comment text — matches Android's ArmorCommentDefaults verbatim. */
    const val DEFAULT_COMMENT: String = "PGPony - PGPony.app"
}

/** Synchronous cache read by the crypto layer. Same contract as the Android original. */
object ArmorCommentHeader {
    /** Validated Comment for message-style armored output, or null for "no Comment header". */
    @Volatile
    var current: String? = ArmorCommentDefaults.DEFAULT_COMMENT

    /** Validated Comment for user-facing PUBLIC KEY exports (ForSharing path), or null. */
    @Volatile
    var pubkeyCurrent: String? = ArmorCommentDefaults.DEFAULT_COMMENT
}
