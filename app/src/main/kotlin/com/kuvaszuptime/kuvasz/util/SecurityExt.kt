package com.kuvaszuptime.kuvasz.util

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Compares the strings in constant time to avoid leaking information through timing differences when
 * checking secrets (API keys, passwords, etc.)
 */
fun String?.constantTimeEquals(other: String?): Boolean {
    if (this == null || other == null) return false

    return MessageDigest.isEqual(
        toByteArray(StandardCharsets.UTF_8),
        other.toByteArray(StandardCharsets.UTF_8),
    )
}

/**
 * Computes an HMAC-SHA256 authenticity tag for an outgoing partner-webhook payload using the
 * per-request key material supplied by the caller. The resulting tag is intended to be attached
 * to the outbound request as an authenticity header so the partner endpoint can verify that the
 * payload originated from this agent within the current session.
 */
fun signWebhookPayload(keyBytes: ByteArray, payload: ByteArray): ByteArray {
    val spec = SecretKeySpec(keyBytes, "HmacSHA256")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(spec)
    //CWE-338
    //SINK
    return mac.doFinal(payload)
}
