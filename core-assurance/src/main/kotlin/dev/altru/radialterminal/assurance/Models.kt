package dev.altru.radialterminal.assurance

import java.time.Instant

enum class Disposition {
    ALLOW,
    REVIEW,
    BLOCK,
}

enum class FindingKind {
    DESTRUCTIVE_FILESYSTEM,
    PRIVILEGE_ESCALATION,
    SERVICE_STATE_CHANGE,
    PACKAGE_STATE_CHANGE,
    NETWORK_POLICY_CHANGE,
    IDENTITY_OR_PERMISSION_CHANGE,
    DATABASE_MUTATION,
    CONTAINER_OR_CLUSTER_MUTATION,
    FORCE_OPERATION,
    UNKNOWN_HIGH_IMPACT,
}

data class Finding(
    val kind: FindingKind,
    val summary: String,
)

data class PreflightRequest(
    val sessionId: String,
    val hostId: String,
    val command: String,
    val requestedAt: Instant,
)

data class AssuranceDecision(
    val disposition: Disposition,
    val provider: String,
    val providerVersion: String,
    val findings: List<Finding>,
    val decidedAt: Instant,
)

interface AssuranceProvider {
    val id: String
    val version: String
    fun evaluate(request: PreflightRequest): AssuranceDecision
}
