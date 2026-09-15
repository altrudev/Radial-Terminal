package dev.altru.radialterminal.assurance

import java.time.Instant
import java.util.concurrent.CancellationException

enum class SessionMode {
    DIRECT,
    GUARDED,
    ASSURED,
}

sealed interface GateResult {
    data class Proceed(val decision: AssuranceDecision) : GateResult
    data class Confirm(val decision: AssuranceDecision) : GateResult
    data class Deny(val decision: AssuranceDecision) : GateResult
}

class CommandGate(
    private val localProvider: AssuranceProvider = BuiltinClassifier(),
    private val assuredProvider: AssuranceProvider? = null,
    private val now: () -> Instant = Instant::now,
) {
    suspend fun evaluate(mode: SessionMode, request: PreflightRequest): GateResult =
        when (mode) {
            SessionMode.DIRECT -> mapDecision(directBypassDecision())
            SessionMode.GUARDED -> mapDecision(evaluateLocalSafely(request))
            SessionMode.ASSURED -> evaluateAssured(request)
        }

    private suspend fun evaluateAssured(request: PreflightRequest): GateResult {
        val local = evaluateLocalSafely(request)
        if (local.disposition == Disposition.BLOCK) {
            return GateResult.Deny(local)
        }

        val external = assuredProvider?.let { evaluateExternalSafely(it, request) }
            ?: degradedDecision("Assured mode has no external assurance provider configured.")

        val freshExternal =
            if (external.validUntil != null && now().isAfter(external.validUntil)) {
                degradedDecision("External assurance decision is stale.")
            } else {
                external
            }

        return mapDecision(combineMonotonically(local, freshExternal))
    }

    private suspend fun evaluateLocalSafely(request: PreflightRequest): AssuranceDecision =
        try {
            localProvider.evaluate(request)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            degradedDecision("Local assurance provider failed; execution requires review.")
        }

    private suspend fun evaluateExternalSafely(
        provider: AssuranceProvider,
        request: PreflightRequest,
    ): AssuranceDecision =
        try {
            validateExternal(provider.evaluate(request))
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            degradedDecision(
                "External assurance provider failed or returned an invalid decision.",
            )
        }

    private fun validateExternal(decision: AssuranceDecision): AssuranceDecision {
        require(decision.provider.isNotBlank()) { "provider must not be blank" }
        require(decision.providerVersion.isNotBlank()) { "provider version must not be blank" }
        require(!decision.assuranceBypassed) { "external provider cannot declare assurance bypass" }
        require(
            decision.validUntil == null || !decision.validUntil.isBefore(decision.decidedAt),
        ) { "validUntil precedes decidedAt" }
        return decision
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

    private fun directBypassDecision() =
        AssuranceDecision(
            disposition = Disposition.ALLOW,
            provider = "direct-bypass",
            providerVersion = "1",
            findings = emptyList(),
            decidedAt = now(),
            assuranceBypassed = true,
        )

    private fun degradedDecision(summary: String) =
        AssuranceDecision(
            disposition = Disposition.REVIEW,
            provider = "assurance-unavailable",
            providerVersion = "1",
            findings = listOf(
                Finding(FindingKind.UNKNOWN_HIGH_IMPACT, summary),
            ),
            decidedAt = now(),
        )
}
