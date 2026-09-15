package dev.altru.radialterminal.assurance

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals

class BuiltinClassifierTest {
    private val classifier = BuiltinClassifier()

    private fun evaluate(command: String): AssuranceDecision =
        classifier.evaluate(
            PreflightRequest(
                sessionId = "session-test",
                hostId = "host-test",
                command = command,
                requestedAt = Instant.EPOCH,
            ),
        )

    @Test
    fun readOnlyCommandIsAllowed() {
        assertEquals(Disposition.ALLOW, evaluate("git status").disposition)
    }

    @Test
    fun serviceRestartRequiresReview() {
        assertEquals(
            Disposition.REVIEW,
            evaluate("sudo systemctl restart nginx").disposition,
        )
    }

    @Test
    fun recursiveForcedRemovalIsBlocked() {
        assertEquals(Disposition.BLOCK, evaluate("rm -rf /var/lib/example").disposition)
    }

    @Test
    fun clusterDeletionRequiresReview() {
        assertEquals(
            Disposition.REVIEW,
            evaluate("kubectl delete deployment api").disposition,
        )
    }
}
