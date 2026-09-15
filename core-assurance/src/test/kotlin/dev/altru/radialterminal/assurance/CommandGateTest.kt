package dev.altru.radialterminal.assurance

import java.time.Instant
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
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
                decidedAt = now,
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
                Disposition.ALLOW,
                validUntil = now.minusSeconds(1),
            ),
            now = { now },
        ).evaluate(SessionMode.ASSURED, request("git status"))

        assertIs<GateResult.Confirm>(result)
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
