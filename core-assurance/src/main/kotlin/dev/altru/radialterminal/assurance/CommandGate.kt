package dev.altru.radialterminal.assurance

import java.time.Instant

enum class SessionMode {
    DIRECT,
    GUARDED,
    ASSURED,
}

sealed interface GateResult {
    data class Execute(
        val decision: AssuranceDecision?,
    ) : GateResult

    data class Confirm(
        val decision: AssuranceDecision,
    ) : GateResult

    data class Deny(
        val decision: AssuranceDecision,
    ) : GateResult
}

/**
 * Maps assurance decisions into operator-facing execution behavior.
 *
 * DIRECT deliberately bypasses assurance evaluation. GUARDED uses the local
 * provider. ASSURED evaluates the external provider when configured and never
 * converts provider failure into ALLOW.
 */
class CommandGate(
    private val localProvider: AssuranceProvider = BuiltinClassifier(),
    private val assuredProvider: AssuranceProvider? = null,
) {
    fun evaluate(mode: SessionMode, request: PreflightRequest): GateResult =
        when (mode) {
            SessionMode.DIRECT -> GateResult.Execute(decision = null)
            SessionMode.GUARDED -> mapDecision(localProvider.evaluate(request))
            SessionMode.ASSURED -> evaluateAssured(request)
        }

    private fun evaluateAssured(request: PreflightRequest): GateResult {
        val provider = assuredProvider
            ?: return GateResult.Confirm(
                degradedDecision(
                    summary = "Assured mode has no external assurance provider configured.",
                ),
            )

        val decision = runCatching { provider.evaluate(request) }
            .getOrElse {
                degradedDecision(
                    summary = "External assurance provider failed; execution requires review.",
                )
            }

        return mapDecision(decision)
    }

    private fun mapDecision(decision: AssuranceDecision): GateResult =
        when (decision.disposition) {
            Disposition.ALLOW -> GateResult.Execute(decision)
            Disposition.REVIEW -> GateResult.Confirm(decision)
            Disposition.BLOCK -> GateResult.Deny(decision)
        }

    private fun degradedDecision(summary: String): AssuranceDecision =
        AssuranceDecision(
            disposition = Disposition.REVIEW,
            provider = "assurance-unavailable",
            providerVersion = "0",
            findings = listOf(
                Finding(
                    kind = FindingKind.UNKNOWN_HIGH_IMPACT,
                    summary = summary,
                ),
            ),
            decidedAt = Instant.now(),
        )
}
