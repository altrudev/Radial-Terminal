package dev.altru.radialterminal.assurance

import java.time.Instant

enum class SessionMode {
    DIRECT,
    GUARDED,
    ASSURED,
}

sealed interface GateResult {
    data class Proceed(
        val decision: AssuranceDecision,
    ) : GateResult

    data class Confirm(
        val decision: AssuranceDecision,
    ) : GateResult

    data class Deny(
        val decision: AssuranceDecision,
    ) : GateResult
}

/**
 * Maps assurance decisions into operator-facing pre-execution behavior.
 *
 * DIRECT deliberately bypasses assurance but still emits provenance.
 * GUARDED uses the local provider.
 * ASSURED always evaluates the local baseline and may only preserve or increase
 * severity when combining with the external provider.
 */
class CommandGate(
    private val localProvider: AssuranceProvider = BuiltinClassifier(),
    private val assuredProvider: AssuranceProvider? = null,
    private val now: () -> Instant = Instant::now,
) {
    suspend fun evaluate(mode: SessionMode, request: PreflightRequest): GateResult =
        when (mode) {
            SessionMode.DIRECT -> mapDecision(directBypassDecision())
            SessionMode.GUARDED -> mapDecision(localProvider.evaluate(request))
            SessionMode.ASSURED -> evaluateAssured(request)
        }

    private suspend fun evaluateAssured(request: PreflightRequest): GateResult {
        val local = localProvider.evaluate(request)

        val external = assuredProvider?.let { provider ->
            runCatching { provider.evaluate(request) }
                .getOrElse {
                    degradedDecision(
                        "External assurance provider failed; execution requires review.",
                    )
                }
        } ?: degradedDecision(
            "Assured mode has no external assurance provider configured.",
        )

        val freshExternal =
            if (external.validUntil != null && now().isAfter(external.validUntil)) {
                degradedDecision("External assurance decision is stale.")
            } else {
                external
            }

        return mapDecision(combineMonotonically(local, freshExternal))
    }

    private fun combineMonotonically(
        local: AssuranceDecision,
        external: AssuranceDecision,
    ): AssuranceDecision {
        val disposition = maxDisposition(local.disposition, external.disposition)
        return AssuranceDecision(
            disposition = disposition,
            provider = "${local.provider}+${external.provider}",
            providerVersion = "${local.providerVersion}+${external.providerVersion}",
            findings = (local.findings + external.findings).distinctBy { it.kind to it.summary },
            decidedAt = maxOf(local.decidedAt, external.decidedAt),
            validUntil = listOfNotNull(local.validUntil, external.validUntil).minOrNull(),
            policyId = external.policyId ?: local.policyId,
            policyVersion = external.policyVersion ?: local.policyVersion,
            assuranceBypassed = false,
        )
    }

    private fun maxDisposition(a: Disposition, b: Disposition): Disposition =
        if (rank(a) >= rank(b)) a else b

    private fun rank(disposition: Disposition): Int =
        when (disposition) {
            Disposition.ALLOW -> 0
            Disposition.REVIEW -> 1
            Disposition.BLOCK -> 2
        }

    private fun mapDecision(decision: AssuranceDecision): GateResult =
        when (decision.disposition) {
            Disposition.ALLOW -> GateResult.Proceed(decision)
            Disposition.REVIEW -> GateResult.Confirm(decision)
            Disposition.BLOCK -> GateResult.Deny(decision)
        }

    private fun directBypassDecision(): AssuranceDecision =
        AssuranceDecision(
            disposition = Disposition.ALLOW,
            provider = "direct-bypass",
            providerVersion = "1",
            findings = emptyList(),
            decidedAt = now(),
            assuranceBypassed = true,
        )

    private fun degradedDecision(summary: String): AssuranceDecision =
        AssuranceDecision(
            disposition = Disposition.REVIEW,
            provider = "assurance-unavailable",
            providerVersion = "1",
            findings = listOf(
                Finding(
                    kind = FindingKind.UNKNOWN_HIGH_IMPACT,
                    summary = summary,
                ),
            ),
            decidedAt = now(),
        )
}
