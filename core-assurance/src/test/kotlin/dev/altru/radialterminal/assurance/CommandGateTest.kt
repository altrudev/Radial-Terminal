package dev.altru.radialterminal.assurance

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class CommandGateTest {
    private fun request(command: String) =
        PreflightRequest(
            sessionId = "session-test",
            hostId = "host-test",
            command = command,
            requestedAt = Instant.EPOCH,
        )

    @Test
    fun directModeDoesNotInvokeAssurance() {
        val provider = object : AssuranceProvider {
            override val id = "must-not-run"
            override val version = "1"

            override fun evaluate(request: PreflightRequest): AssuranceDecision =
                error("provider should not be invoked")
        }

        val result = CommandGate(localProvider = provider).evaluate(
            SessionMode.DIRECT,
            request("rm -rf /"),
        )

        assertIs<GateResult.Execute>(result)
    }

    @Test
    fun guardedReviewRequiresConfirmation() {
        val result = CommandGate().evaluate(
            SessionMode.GUARDED,
            request("sudo systemctl restart nginx"),
        )

        assertIs<GateResult.Confirm>(result)
    }

    @Test
    fun guardedBlockIsDenied() {
        val result = CommandGate().evaluate(
            SessionMode.GUARDED,
            request("rm -rf /var/lib/example"),
        )

        assertIs<GateResult.Deny>(result)
    }

    @Test
    fun assuredModeWithoutProviderFailsToReview() {
        val result = CommandGate().evaluate(
            SessionMode.ASSURED,
            request("git status"),
        )

        val confirm = assertIs<GateResult.Confirm>(result)
        assertEquals("assurance-unavailable", confirm.decision.provider)
    }

    @Test
    fun assuredProviderFailureNeverBecomesAllow() {
        val provider = object : AssuranceProvider {
            override val id = "broken"
            override val version = "1"

            override fun evaluate(request: PreflightRequest): AssuranceDecision =
                error("network failure")
        }

        val result = CommandGate(assuredProvider = provider).evaluate(
            SessionMode.ASSURED,
            request("git status"),
        )

        assertIs<GateResult.Confirm>(result)
    }
}
