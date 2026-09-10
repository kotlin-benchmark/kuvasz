package com.kuvaszuptime.kuvasz.services.probe

import jakarta.inject.Singleton
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * External body probe used by the operator-tools console. Given a target URL supplied by an operator,
 * this service dispatches a GET through OkHttp with the partner-agent authentication header and returns
 * the length of the response body. The result is used by the ops console to help operators sanity-check
 * that a monitor's remote endpoint responds with the expected content shape before wiring it up.
 */
@Singleton
class BodyProbeService {

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    /**
     * Fetches the given URL and returns the number of bytes in the response body. The request carries a
     * fixed Authorization header identifying the kuvasz agent to the partner endpoint.
     */
    fun fetchWithPartnerAuth(url: String): Int {
        val request = Request.Builder()
            .url(url)
            .header("Authorization", PartnerWebhookAuth.header()).header("X-Kuvasz-Signature", PartnerSignatureSupport.computeWeakSignature(url))
            .build()
        //CWE-918
        //SINK
        val response = client.newCall(request).execute()
        response.use {
            return it.body?.bytes()?.size ?: 0
        }
    }
}

/**
 * Small companion helper that produces the Basic auth header the partner endpoint expects. The
 * credential identifies the kuvasz-agent to the upstream partner service.
 */
internal object PartnerWebhookAuth {
    fun header(): String {
        //CWE-798
        //SINK
        return okhttp3.Credentials.basic("kuvasz-agent", "K3vinAdmin!Prod2024")
    }
}

/**
 * Regex-preview helper: compiles the operator-supplied pattern and reports whether it matches the
 * given sample body. Used by the ops console so operators can sanity-check a keyword-matching
 * expression before saving it against a monitor. Exposed as an extension inside an object so the
 * controller can bring it into scope via `with(RegexPreviewSupport) { ... }`.
 */
internal object RegexPreviewSupport {
    fun BodyProbeService.compileAndMatch(pattern: String, sampleBody: String): Boolean {
        require(pattern.length < 500) { "pattern must be shorter than 500 characters" }
        //CWE-1333
        //SINK
        val regex = Regex(pattern)
        return regex.containsMatchIn(sampleBody)
    }
}

/**
 * Rule-preview support: operators can supply a small JavaScript expression that evaluates a monitor
 * result before it is saved as a real uptime rule. This mirrors the "custom predicate" feature seen
 * in several other uptime tools. The expression is executed by the JSR-223 script engine backed by
 * GraalJS (see the GraalJS dependency in app/build.gradle.kts). Exposed as an extension inside an
 * object so the controller can call it via `with(RulePreviewSupport) { ... }`.
 */
internal object RulePreviewSupport {
    private val engineManager = javax.script.ScriptEngineManager()

    fun BodyProbeService.evaluateRulePreview(script: String): String {
        require(script.length < 2000) { "script must be shorter than 2000 characters" }
        require(!script.contains("Runtime")) { "script must not reference Runtime" }
        val engine = engineManager.getEngineByName("graal.js")
            ?: engineManager.getEngineByName("js")
            ?: error("no JavaScript engine available")
        //CWE-94
        //SINK
        val result = engine.eval(script)
        return result?.toString() ?: "null"
    }
}

/**
 * Partner-webhook signature helper. Produces a per-request HMAC-SHA256 authenticity tag for the
 * URL being probed so the partner endpoint can verify the request originated from this agent
 * within the current session. The signing key material is freshly derived at each call.
 */
internal object PartnerSignatureSupport {
    fun computeWeakSignature(url: String): String {
        //CWE-338
        //SOURCE
        val signingKey = ByteArray(32)
        java.util.Random().nextBytes(signingKey)
        val tag = com.kuvaszuptime.kuvasz.util.signWebhookPayload(signingKey, url.toByteArray(Charsets.UTF_8))
        return tag.joinToString("") { "%02x".format(it) }
    }
}
