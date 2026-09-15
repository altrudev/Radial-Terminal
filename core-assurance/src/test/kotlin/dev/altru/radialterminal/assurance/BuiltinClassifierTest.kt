package dev.altru.radialterminal.assurance

import java.time.Instant
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class BuiltinClassifierTest {
    private val classifier = BuiltinClassifier()

    private suspend fun evaluate(command: String): AssuranceDecision =
        classifier.evaluate(
            PreflightRequest(
                sessionId = "session-test",
                hostId = "host-test",
                command = command,
                requestedAt = Instant.EPOCH,
            ),
        )

    @Test
    fun recognizedReadOnlyCommandIsAllowed() = runTest {
        assertEquals(Disposition.ALLOW, evaluate("git status").disposition)
    }

    @Test
    fun unknownCommandRequiresReview() = runTest {
        assertEquals(Disposition.REVIEW, evaluate("mystery-tool --do-something").disposition)
    }

    @Test
    fun tailFollowDoesNotTriggerGenericForceFinding() = runTest {
        assertEquals(Disposition.ALLOW, evaluate("tail -f app.log").disposition)
    }

    @Test
    fun shellRedirectionPreventsLowRiskAllow() = runTest {
        assertEquals(Disposition.REVIEW, evaluate("ls > inventory.txt").disposition)
    }

    @Test
    fun quotedRmWordDoesNotBecomeDestructiveRemoval() = runTest {
        assertEquals(Disposition.REVIEW, evaluate("echo rm").disposition)
    }

    @Test
    fun gitBranchMutationIsNotLowRiskAllowed() = runTest {
        assertEquals(Disposition.REVIEW, evaluate("git branch -D release").disposition)
    }

    @Test
    fun findDeleteIsNotLowRiskAllowed() = runTest {
        assertEquals(Disposition.REVIEW, evaluate("find . -delete").disposition)
    }

    @Test
    fun serviceRestartRequiresReview() = runTest {
        assertEquals(
            Disposition.REVIEW,
            evaluate("sudo systemctl restart nginx").disposition,
        )
    }

    @Test
    fun fileRemovalIsBlocked() = runTest {
        assertEquals(Disposition.BLOCK, evaluate("rm notes.txt").disposition)
    }

    @Test
    fun sudoFileRemovalIsBlocked() = runTest {
        assertEquals(Disposition.BLOCK, evaluate("sudo rm notes.txt").disposition)
    }

    @Test
    fun recursiveForcedRemovalIsBlocked() = runTest {
        assertEquals(Disposition.BLOCK, evaluate("rm -rf /var/lib/example").disposition)
    }

    @Test
    fun filesystemFormatIsBlocked() = runTest {
        assertEquals(Disposition.BLOCK, evaluate("mkfs.ext4 /dev/sdb1").disposition)
    }

    @Test
    fun rawDeviceWriteIsBlocked() = runTest {
        assertEquals(Disposition.BLOCK, evaluate("dd if=image.img of=/dev/sdb").disposition)
    }

    @Test
    fun clusterDeletionRequiresReview() = runTest {
        assertEquals(
            Disposition.REVIEW,
            evaluate("kubectl delete deployment api").disposition,
        )
    }

    @Test
    fun oversizedCommandRequiresReview() = runTest {
        assertEquals(
            Disposition.REVIEW,
            evaluate("x".repeat(BuiltinClassifier.MAX_COMMAND_CHARS + 1)).disposition,
        )
    }
}
