package dev.altru.radialterminal.assurance

import java.time.Instant

/**
 * Conservative, local-only classifier.
 *
 * This is intentionally not a shell semantic prover. It identifies command
 * patterns that deserve additional operator attention.
 */
class BuiltinClassifier : AssuranceProvider {
    override val id: String = "builtin-static"
    override val version: String = "0.1.0"

    override fun evaluate(request: PreflightRequest): AssuranceDecision {
        val command = request.command.trim()
        val findings = mutableListOf<Finding>()

        fun mark(regex: Regex, kind: FindingKind, summary: String) {
            if (regex.containsMatchIn(command)) {
                findings += Finding(kind, summary)
            }
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
            Regex("""(--force|-f)\b""", RegexOption.IGNORE_CASE),
            FindingKind.FORCE_OPERATION,
            "Force option detected.",
        )

        val disposition = when {
            findings.any {
                it.kind == FindingKind.DESTRUCTIVE_FILESYSTEM ||
                    it.kind == FindingKind.DATABASE_MUTATION
            } -> Disposition.BLOCK

            findings.isNotEmpty() -> Disposition.REVIEW
            else -> Disposition.ALLOW
        }

        return AssuranceDecision(
            disposition = disposition,
            provider = id,
            providerVersion = version,
            findings = findings.distinctBy { it.kind },
            decidedAt = Instant.now(),
        )
    }
}
