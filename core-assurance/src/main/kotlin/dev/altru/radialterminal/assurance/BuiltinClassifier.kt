package dev.altru.radialterminal.assurance

import java.time.Instant

/**
 * Conservative, local-only classifier.
 *
 * This is intentionally not a shell semantic prover. It identifies command
 * patterns that deserve additional operator attention and only ALLOWs a small,
 * explicit set of recognized low-risk command families.
 */
class BuiltinClassifier : AssuranceProvider {
    override val id: String = "builtin-static"
    override val version: String = "0.2.0"

    override suspend fun evaluate(request: PreflightRequest): AssuranceDecision {
        val command = request.command.trim()
        val findings = mutableListOf<Finding>()

        if (request.sessionId.isBlank() || request.hostId.isBlank() || command.isBlank()) {
            findings += Finding(
                FindingKind.INVALID_REQUEST,
                "Session, host, and command must all be present.",
            )
            return decision(Disposition.REVIEW, findings)
        }

        if (command.length > MAX_COMMAND_CHARS) {
            findings += Finding(
                FindingKind.OVERSIZED_COMMAND,
                "Command exceeds the local preflight size limit.",
            )
            return decision(Disposition.REVIEW, findings)
        }

        fun mark(regex: Regex, kind: FindingKind, summary: String) {
            if (regex.containsMatchIn(command)) findings += Finding(kind, summary)
        }

        mark(
            Regex("""(^|[;&|]\s*)sudo\b""", RegexOption.IGNORE_CASE),
            FindingKind.PRIVILEGE_ESCALATION,
            "Command requests elevated execution authority.",
        )
        mark(
            Regex("""\brm\s+[^\n]*(-[^\n]*r[^\n]*f|-rf|-fr)\b""", RegexOption.IGNORE_CASE),
            FindingKind.DESTRUCTIVE_FILESYSTEM,
            "Recursive forced removal detected.",
        )
        mark(
            Regex("""\bmkfs(?:\.[A-Za-z0-9_-]+)?\b""", RegexOption.IGNORE_CASE),
            FindingKind.FILESYSTEM_FORMAT,
            "Filesystem formatting operation detected.",
        )
        mark(
            Regex("""\bdd\b[^\n]*\bof=/dev/""", RegexOption.IGNORE_CASE),
            FindingKind.RAW_DEVICE_WRITE,
            "Raw device write detected.",
        )
        mark(
            Regex("""\b(shutdown|reboot|poweroff|halt)\b""", RegexOption.IGNORE_CASE),
            FindingKind.SYSTEM_POWER_CHANGE,
            "System power-state change detected.",
        )
        mark(
            Regex("""\bterraform\s+destroy\b""", RegexOption.IGNORE_CASE),
            FindingKind.INFRASTRUCTURE_DESTROY,
            "Infrastructure destruction operation detected.",
        )
        mark(
            Regex("""\b(systemctl|service)\s+(stop|disable|mask|restart)\b""", RegexOption.IGNORE_CASE),
            FindingKind.SERVICE_STATE_CHANGE,
            "Service state mutation detected.",
        )
        mark(
            Regex("""\b(apt|apt-get|dnf|yum|pacman)\s+(remove|purge|autoremove|erase)\b""", RegexOption.IGNORE_CASE),
            FindingKind.PACKAGE_STATE_CHANGE,
            "Package removal detected.",
        )
        mark(
            Regex("""\b(iptables|nft|ufw|firewall-cmd)\b""", RegexOption.IGNORE_CASE),
            FindingKind.NETWORK_POLICY_CHANGE,
            "Network policy mutation may occur.",
        )
        mark(
            Regex("""\b(chmod|chown|userdel|groupdel|passwd)\b""", RegexOption.IGNORE_CASE),
            FindingKind.IDENTITY_OR_PERMISSION_CHANGE,
            "Identity or permission state may change.",
        )
        mark(
            Regex("""\b(drop\s+(database|table)|truncate\s+table)\b""", RegexOption.IGNORE_CASE),
            FindingKind.DATABASE_MUTATION,
            "Potentially destructive database mutation detected.",
        )
        mark(
            Regex("""\b(docker\s+system\s+prune|kubectl\s+delete|helm\s+uninstall)\b""", RegexOption.IGNORE_CASE),
            FindingKind.CONTAINER_OR_CLUSTER_MUTATION,
            "Container or cluster state mutation detected.",
        )
        mark(
            Regex("""\bgit\s+push\b[^\n]*(--force(?:-with-lease)?|-f)\b""", RegexOption.IGNORE_CASE),
            FindingKind.FORCE_OPERATION,
            "Forced Git push detected.",
        )

        val distinct = findings.distinctBy { it.kind }
        val disposition = when {
            distinct.any { it.kind in BLOCKING_KINDS } -> Disposition.BLOCK
            distinct.isNotEmpty() -> Disposition.REVIEW
            isRecognizedLowRisk(command) -> Disposition.ALLOW
            else -> {
                findings += Finding(
                    FindingKind.UNRECOGNIZED_COMMAND,
                    "Command is not in the local low-risk allowlist; operator review required.",
                )
                Disposition.REVIEW
            }
        }

        return decision(disposition, findings.distinctBy { it.kind })
    }

    private fun decision(
        disposition: Disposition,
        findings: List<Finding>,
    ) = AssuranceDecision(
        disposition = disposition,
        provider = id,
        providerVersion = version,
        findings = findings,
        decidedAt = Instant.now(),
    )

    private fun isRecognizedLowRisk(command: String): Boolean =
        LOW_RISK_PATTERNS.any { it.matches(command) }

    companion object {
        const val MAX_COMMAND_CHARS = 16_384

        private val BLOCKING_KINDS = setOf(
            FindingKind.DESTRUCTIVE_FILESYSTEM,
            FindingKind.DATABASE_MUTATION,
            FindingKind.FILESYSTEM_FORMAT,
            FindingKind.RAW_DEVICE_WRITE,
            FindingKind.INFRASTRUCTURE_DESTROY,
        )

        private val LOW_RISK_PATTERNS = listOf(
            Regex("""\s*(pwd|whoami|id|hostname|uname(?:\s+.*)?|date)\s*""", RegexOption.IGNORE_CASE),
            Regex("""\s*git\s+(status|diff|log|show|branch)(?:\s+.*)?""", RegexOption.IGNORE_CASE),
            Regex("""\s*(ls|find|stat|du|df)(?:\s+.*)?""", RegexOption.IGNORE_CASE),
            Regex("""\s*(cat|head|tail|less|more)(?:\s+.*)?""", RegexOption.IGNORE_CASE),
            Regex("""\s*(ps|top|uptime|free)(?:\s+.*)?""", RegexOption.IGNORE_CASE),
        )
    }
}
