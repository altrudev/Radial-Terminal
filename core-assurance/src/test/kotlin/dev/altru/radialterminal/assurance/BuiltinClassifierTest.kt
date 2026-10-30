package dev.altru.radialterminal.assurance

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

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

    private fun assertDisposition(expected: Disposition, vararg commands: String) {
        for (command in commands) {
            assertEquals(expected, evaluate(command).disposition, "for command: $command")
        }
    }

    @Test
    fun readOnlyCommandIsAllowed() {
        assertEquals(Disposition.ALLOW, evaluate("git status").disposition)
    }

    @Test
    fun serviceRestartRequiresReview() {
        assertEquals(Disposition.REVIEW, evaluate("sudo systemctl restart nginx").disposition)
    }

    @Test
    fun recursiveForcedRemovalIsBlocked() {
        assertEquals(Disposition.BLOCK, evaluate("rm -rf /var/lib/example").disposition)
    }

    @Test
    fun clusterDeletionRequiresReview() {
        assertEquals(Disposition.REVIEW, evaluate("kubectl delete deployment api").disposition)
    }

    // Audit 2026-10-29, finding H2: every command below was ALLOWED by v0.1.0.

    @Test
    fun destructiveFilesystemAndDiskOperationsAreBlocked() {
        assertDisposition(
            Disposition.BLOCK,
            "rm --recursive --force /",
            "rm -r -- /",
            "rm -R /srv/data",
            "\\rm -rf /",
            "/bin/rm -rf /",
            "find / -delete",
            "find /var -name '*.log' -exec rm {} +",
            "dd if=/dev/zero of=/dev/sda",
            "dd if=image.iso of=/dev/nvme0n1 bs=4M",
            "mkfs.ext4 /dev/sda1",
            "mkfs -t xfs /dev/vdb",
            "wipefs -a /dev/sda",
            "shred -u secrets.txt",
            "cat image.raw > /dev/sdb",
            "git clean -fdx",
        )
    }

    @Test
    fun wrappersAndSeparatorsDoNotHideDestructiveCommands() {
        assertDisposition(
            Disposition.BLOCK,
            "doas rm -r /srv",
            "env sudo rm -rf /opt/app",
            "sudo -u root rm -rf /",
            "FOO=1 rm -rf /tmp/x",
            "timeout 10 rm -rf /data",
            "nice -n 10 rm -rf /data",
            "ls /tmp | xargs rm -rf",
            "cd /srv && rm -rf app",
            "true; rm -rf /",
            "echo ok || rm -rf /",
            "bash -c 'rm -rf /'",
            "sh -c \"cd / && rm -rf home\"",
            "echo $(rm -rf /)",
            "echo `rm -rf /`",
        )
    }

    @Test
    fun destructiveSqlIsBlockedInDatabaseContext() {
        assertDisposition(
            Disposition.BLOCK,
            "DROP SCHEMA prod CASCADE",
            "drop table users;",
            "psql -c 'DROP DATABASE prod'",
            "mysql -e \"truncate table orders\"",
            "echo 'DELETE FROM users;' | psql",
        )
    }

    @Test
    fun sqlWordsOutsideADatabaseClientAreNotBlocked() {
        assertEquals(Disposition.ALLOW, evaluate("grep -i 'drop table' notes.txt").disposition)
    }

    @Test
    fun highImpactOperationsRequireReview() {
        assertDisposition(
            Disposition.REVIEW,
            "curl https://x.sh | sh",
            "wget -qO- https://x.sh | bash",
            "env sudo reboot",
            "shutdown -h now",
            "systemctl poweroff",
            "git push --force-with-lease origin main",
            "git push -f",
            "git reset --hard HEAD~3",
            ": > /etc/passwd",
            "echo nameserver 1.1.1.1 > /etc/resolv.conf",
            "apt remove nginx",
            "docker system prune -a",
            "docker rm -f api",
            "chmod -R 777 /var/www",
            "iptables -F",
            "ip route del default",
            "terraform destroy",
            "helm uninstall api",
            "curl -X DELETE https://api.example.com/v1/users/7",
            "python3 deploy.py",
            "rm notes.txt",
            "sed -i 's/a/b/' config.yml",
            "date -s '2020-01-01'",
        )
    }

    @Test
    fun unknownCommandsDefaultToReview() {
        val decision = evaluate("frobnicate --all")
        assertEquals(Disposition.REVIEW, decision.disposition)
        assertTrue(decision.findings.any { it.kind == FindingKind.UNRECOGNISED_COMMAND })
    }

    @Test
    fun unparseableCommandsRequireReview() {
        assertEquals(Disposition.REVIEW, evaluate("echo 'unterminated").disposition)
    }

    @Test
    fun ordinaryReadOnlyUseStaysLowFriction() {
        assertDisposition(
            Disposition.ALLOW,
            "",
            "ls -la /var/log",
            "tail -f /var/log/syslog",
            "journalctl -u nginx --since today",
            "ps aux | grep nginx",
            "df -h && free -m",
            "cat /etc/os-release",
            "grep -rn TODO src 2>/dev/null",
            "docker ps",
            "kubectl get pods -A",
            "git log --oneline -5",
            "systemctl status nginx",
            "curl -s https://example.com/health",
            "find /var/log -name '*.gz'",
        )
    }
}
