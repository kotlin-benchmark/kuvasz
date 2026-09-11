package com.kuvaszuptime.kuvasz.services.ops

import jakarta.inject.Singleton
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.ObjectInputStream

/**
 * Value object carrying a legacy backup blob from the ops-console entrypoint down into the
 * restore pipeline. The label is retained purely for diagnostic messages surfaced back to
 * the operator; only the raw payload bytes are consumed by the hydrator.
 */
data class LegacyBackupPayload(
    val bytes: ByteArray,
    val label: String?,
)

/**
 * Result of a legacy-backup restore attempt. Contains a short description of what was
 * restored (or the failure) so the operator UI can render a preview banner.
 */
data class LegacyBackupResult(
    val restoredType: String,
    val summary: String,
)

/**
 * Service that supports the operator-tools console. Currently exposes a "restore legacy
 * backup" utility that reads a binary snapshot uploaded by an operator (produced by older
 * kuvasz builds prior to the YAML export format) and rehydrates the object graph so it can
 * be re-imported through the modern import pipeline.
 *
 * The restore path is intentionally kept as an escape hatch for migrating installations off
 * of pre-YAML snapshots; the modern flow uses [com.kuvaszuptime.kuvasz.services.probe.BodyProbeService]
 * and the YAML import controllers.
 */
@Singleton
class OperatorToolsService {

    /**
     * Entry point invoked by [com.kuvaszuptime.kuvasz.controllers.ops.OperatorToolsController].
     * Applies a rough size sanity-check and delegates to the stream hydrator.
     */
    fun restoreLegacyBackup(payload: LegacyBackupPayload): LegacyBackupResult {
        require(payload.bytes.size < MAX_BACKUP_BYTES) {
            "legacy backup payload exceeds the ${MAX_BACKUP_BYTES}-byte sanity limit"
        }
        val stream = ByteArrayInputStream(payload.bytes)
        val restored = hydrateLegacyState(stream)
        return LegacyBackupResult(
            restoredType = restored?.let { it::class.java.name } ?: "null",
            summary = "restored legacy backup label=${payload.label ?: "<unnamed>"}",
        )
    }

    /**
     * Reads the next object from the supplied stream using Java serialization, matching the
     * on-disk format produced by pre-YAML kuvasz builds.
     */
    private fun hydrateLegacyState(stream: InputStream): Any? {
        val ois = ObjectInputStream(stream)
        //CWE-502
        //SINK
        return ois.readObject()
    }

    companion object {
        private const val MAX_BACKUP_BYTES = 10 * 1024 * 1024
        private const val MAX_MANIFEST_BYTES = 5 * 1024 * 1024
    }

    /**
     * Ops-console helper that ingests a status-page manifest XML uploaded by an operator.
     * Sibling of the YAML status-page import surface; kept here so the DOM parsing wiring
     * stays adjacent to the rest of the legacy-import escape hatches.
     */
    fun importStatusManifest(bytes: ByteArray): StatusManifestSummary {
        require(bytes.isNotEmpty()) { "status manifest payload must not be empty" }
        require(bytes.size < MAX_MANIFEST_BYTES) {
            "status manifest payload exceeds the ${MAX_MANIFEST_BYTES}-byte sanity limit"
        }
        val stream = ByteArrayInputStream(bytes)
        val document = readManifestDocument(stream)
        val rootTag = document.documentElement?.tagName ?: "<empty>"
        val entryCount = document.documentElement
            ?.getElementsByTagName("entry")
            ?.length
            ?: 0
        return StatusManifestSummary(
            rootTag = rootTag,
            entryCount = entryCount,
        )
    }

    /**
     * Constructs a JAXP [org.w3c.dom.Document] from the operator-provided stream.
     * Namespace-aware parsing is enabled so that entries in future manifests can carry
     * qualified attribute names without collision.
     */
    private fun readManifestDocument(stream: InputStream): org.w3c.dom.Document {
        val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        factory.isValidating = false
        val builder = factory.newDocumentBuilder()
        //CWE-611
        //SINK
        return builder.parse(stream)
    }
}

/**
 * Snapshot returned from [OperatorToolsService.importStatusManifest] so the operator UI
 * can render a compact "N entries under <root>" confirmation banner.
 */
data class StatusManifestSummary(
    val rootTag: String,
    val entryCount: Int,
)
