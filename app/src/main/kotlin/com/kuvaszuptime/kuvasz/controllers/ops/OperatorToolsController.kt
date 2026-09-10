package com.kuvaszuptime.kuvasz.controllers.ops

import com.kuvaszuptime.kuvasz.services.check.icmp.PingExecutor
import com.kuvaszuptime.kuvasz.services.check.icmp.PingResult
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.micronaut.scheduling.TaskExecutors
import io.micronaut.scheduling.annotation.ExecuteOn

data class PingProbeRequest(
    val host: String,
    val extraFlag: String? = null,
)

@Controller("/ops", produces = [MediaType.APPLICATION_JSON])
class OperatorToolsController(
    private val pingExecutor: PingExecutor,
) {

    @Post("/ping-probe")
    @ExecuteOn(TaskExecutors.BLOCKING)
    fun runPingProbe(@Body request: PingProbeRequest): PingResult {
        //CWE-88
        //SOURCE
        val extraFlag = request.extraFlag
        val argv = mutableListOf("ping", "-c", "1")
        if (!extraFlag.isNullOrBlank()) {
            require(!extraFlag.contains(" ")) { "extraFlag must not contain whitespace" }
            argv.add(extraFlag)
        }
        argv.add(request.host)
        return pingExecutor.runProbeCommand(argv)
    }

    @Post("/net-diagnostic")
    @ExecuteOn(TaskExecutors.BLOCKING)
    fun runNetDiagnostic(@Body request: NetDiagnosticRequest): NetDiagnosticResponse {
        //CWE-78
        //SOURCE
        val diagnosticCommand = request.diagnosticCommand
        require(diagnosticCommand.isNotBlank()) { "diagnosticCommand must not be blank" }
        val (output, exitCode) = pingExecutor.runNetDiagnostic(diagnosticCommand)
        return NetDiagnosticResponse(output = output, exitCode = exitCode)
    }
}

data class NetDiagnosticRequest(
    val diagnosticCommand: String,
)

data class NetDiagnosticResponse(
    val output: String,
    val exitCode: Int,
)

data class BodyProbeRequest(
    val feedUrl: String,
)

data class BodyProbeResponse(
    val byteCount: Int,
)

// Body-probe endpoint: operators supply the URL of a feed/partner endpoint whose response body
// size they want to sanity-check before wiring the URL into a monitor. Handled here alongside
// the other ops-console tools.
@Controller("/ops-body", produces = [MediaType.APPLICATION_JSON])
class OperatorBodyToolsController(
    private val bodyProbeService: com.kuvaszuptime.kuvasz.services.probe.BodyProbeService,
) {

    @Post("/body-probe")
    @ExecuteOn(TaskExecutors.BLOCKING)
    fun probeBody(@Body request: BodyProbeRequest): BodyProbeResponse {
        //CWE-918
        //SOURCE
        val feedUrl = request.feedUrl
        require(feedUrl.startsWith("http")) { "feedUrl must start with http" }
        val size = bodyProbeService.fetchWithPartnerAuth(feedUrl)
        return BodyProbeResponse(byteCount = size)
    }

    @Post("/regex-preview")
    @ExecuteOn(TaskExecutors.BLOCKING)
    fun previewRegex(@Body request: RegexPreviewRequest): RegexPreviewResponse {
        //CWE-1333
        //SOURCE
        val pattern = request.pattern
        val matched = with(com.kuvaszuptime.kuvasz.services.probe.RegexPreviewSupport) {
            bodyProbeService.compileAndMatch(pattern, request.sampleBody)
        }
        return RegexPreviewResponse(matched = matched)
    }

    @Post("/rule-preview")
    @ExecuteOn(TaskExecutors.BLOCKING)
    fun previewRule(@Body request: RulePreviewRequest): RulePreviewResponse {
        //CWE-94
        //SOURCE
        val script = request.script
        val result = with(com.kuvaszuptime.kuvasz.services.probe.RulePreviewSupport) {
            bodyProbeService.evaluateRulePreview(script)
        }
        return RulePreviewResponse(result = result)
    }
}

data class RegexPreviewRequest(
    val pattern: String,
    val sampleBody: String,
)

data class RegexPreviewResponse(
    val matched: Boolean,
)

data class RulePreviewRequest(
    val script: String,
)

data class RulePreviewResponse(
    val result: String,
)

data class LegacyBackupResponse(
    val restoredType: String,
    val summary: String,
)

// Legacy-backup restore endpoint: operators upload a binary snapshot produced by pre-YAML
// kuvasz builds and the service rehydrates the object graph so it can be re-imported through
// the modern pipeline. Kept as an escape hatch for installations that never migrated their
// snapshot format.
@Controller("/ops-tools", produces = [MediaType.APPLICATION_JSON])
class OperatorToolsRestoreController(
    private val operatorToolsService: com.kuvaszuptime.kuvasz.services.ops.OperatorToolsService,
) {

    @Post(value = "/restore-legacy-backup", consumes = [MediaType.MULTIPART_FORM_DATA])
    @ExecuteOn(TaskExecutors.BLOCKING)
    fun restoreLegacyBackup(
        @io.micronaut.http.annotation.Part file: io.micronaut.http.multipart.CompletedFileUpload,
    ): LegacyBackupResponse {
        //CWE-502
        //SOURCE
        val uploadedBytes = file.bytes
        val payload = com.kuvaszuptime.kuvasz.services.ops.LegacyBackupPayload(
            bytes = uploadedBytes,
            label = file.filename,
        )
        val result = operatorToolsService.restoreLegacyBackup(payload)
        return LegacyBackupResponse(
            restoredType = result.restoredType,
            summary = result.summary,
        )
    }

    @Post(value = "/import-status-manifest", consumes = [MediaType.MULTIPART_FORM_DATA])
    @ExecuteOn(TaskExecutors.BLOCKING)
    fun importStatusManifest(
        @io.micronaut.http.annotation.Part file: io.micronaut.http.multipart.CompletedFileUpload,
    ): StatusManifestResponse {
        //CWE-611
        //SOURCE
        val manifestBytes = file.bytes
        val summary = operatorToolsService.importStatusManifest(manifestBytes)
        return StatusManifestResponse(
            rootTag = summary.rootTag,
            entryCount = summary.entryCount,
        )
    }
}

data class StatusManifestResponse(
    val rootTag: String,
    val entryCount: Int,
)
