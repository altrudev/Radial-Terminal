package dev.altru.radialterminal.assurance

import java.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class CommandGateTest {
    private val now = Instant.parse("2026-09-15T00:00:00Z")

    private fun request(command: String) =
        PreflightRequest(
            sessionId = "session-test",
            hostId = "host-test",
            command = command,
            requestedAt = now,
        )

    private fun provider(
        disposition: Disposition,
        decidedAt: Instant = now,
        validUntil: Instant? = null,
    ) = object : AssuranceProvider {
        override val id = "external-test"
        override val version = "1"

        override suspend fun evaluate(request: PreflightRequest) =
            AssuranceDecision(
                disposition = disposition,
                provider = id,
                providerVersion = version,
                findings = emptyList(),
                decidedAt = decidedAt,
                validUntil = validUntil,
            )
    }

    @Test
    fun directModeDoesNotInvokeAssuranceAndRecordsBypass() = runTest {
        val provider = object : AssuranceProvider {
            override val id = "must-not-run"
            override val version = "1"

            override suspend fun evaluate(request: PreflightRequest): AssuranceDecision =
                error("provider should not be invoked")
        }

        val result = CommandGate(
            localProvider = provider,
            now = { now },
        ).evaluate(SessionMode.DIRECT, request("rm -rf /"))

        val proceed = assertIs<GateResult.Proceed>(result)
        assertTrue(proceed.decision.assuranceBypassed)
        assertEquals("direct-bypass", proceed.decision.provider)
    }

    @Test
    fun guardedReviewRequiresConfirmation() = runTest {
        assertIs<GateResult.Confirm>(
            CommandGate(now = { now }).evaluate(
                SessionMode.GUARDED,
                request("sudo systemctl restart nginx"),
            ),
        )
    }

    @Test
    fun guardedBlockIsDenied() = runTest {
        assertIs<GateResult.Deny>(
            CommandGate(now = { now }).evaluate(
                SessionMode.GUARDED,
                request("rm -rf /var/lib/example"),
            ),
        )
    }

    @Test
    fun localProviderFailureDegradesToReview() = runTest {
        val broken = object : AssuranceProvider {
            override val id = "broken-local"
            override val version = "1"
            override suspend fun evaluate(request: PreflightRequest): AssuranceDecision =
                error("local failure")
        }

        assertIs<GateResult.Confirm>(
            CommandGate(localProvider = broken, now = { now })
                .evaluate(SessionMode.GUARDED, request("git status")),
        )
    }

    @Test
    fun assuredExternalAllowCannotDowngradeLocalBlock() = runTest {
        val result = CommandGate(
            assuredProvider = provider(Disposition.ALLOW),
            now = { now },
        ).evaluate(SessionMode.ASSURED, request("rm -rf /var/lib/example"))

        assertIs<GateResult.Deny>(result)
    }

    @Test
    fun assuredExternalBlockEscalatesLocalAllow() = runTest {
        val result = CommandGate(
            assuredProvider = provider(Disposition.BLOCK),
            now = { now },
        ).evaluate(SessionMode.ASSURED, request("git status"))

        assertIs<GateResult.Deny>(result)
    }

    @Test
    fun assuredModeWithoutProviderRequiresReview() = runTest {
        val result = CommandGate(now = { now }).evaluate(
            SessionMode.ASSURED,
            request("git status"),
        )

        val confirm = assertIs<GateResult.Confirm>(result)
        assertTrue(confirm.decision.provider.contains("assurance-unavailable"))
    }

    @Test
    fun staleExternalAllowRequiresReview() = runTest {
        val result = CommandGate(
            assuredProvider = provider(
                disposition = Disposition.ALLOW,
                decidedAt = now.minusSeconds(10),
                validUntil = now.minusSeconds(1),
            ),
            now = { now },
        ).evaluate(SessionMode.ASSURED, request("git status"))

        assertIs<GateResult.Confirm>(result)
    }

    @Test
    fun malformedExternalDecisionRequiresReview() = runTest {
        val malformed = object : AssuranceProvider {
            override val id = "malformed"
            override val version = "1"
            override suspend fun evaluate(request: PreflightRequest) =
                AssuranceDecision(
                    disposition = Disposition.ALLOW,
                    provider = "",
                    providerVersion = "",
                    findings = emptyList(),
                    decidedAt = now,
                )
        }

        assertIs<GateResult.Confirm>(
            CommandGate(assuredProvider = malformed, now = { now })
                .evaluate(SessionMode.ASSURED, request("git status")),
        )
    }

    @Test
    fun cancellationIsNotConvertedToReview() = runTest {
        val cancelled = object : AssuranceProvider {
            override val id = "cancelled"
            override val version = "1"
            override suspend fun evaluate(request: PreflightRequest): AssuranceDecision =
                throw CancellationException("cancel")
        }

        assertFailsWith<CancellationException> {
            CommandGate(assuredProvider = cancelled, now = { now })
                .evaluate(SessionMode.ASSURED, request("git status"))
        }
    }

    @Test
    fun assuredProviderFailureNeverBecomesAllow() = runTest {
        val provider = object : AssuranceProvider {
            override val id = "broken"
            override val version = "1"

            override suspend fun evaluate(request: PreflightRequest): AssuranceDecision =
                error("network failure")
        }

        assertIs<GateResult.Confirm>(
            CommandGate(
                assuredProvider = provider,
                now = { now },
            ).evaluate(SessionMode.ASSURED, request("git status")),
        )
    }
}
