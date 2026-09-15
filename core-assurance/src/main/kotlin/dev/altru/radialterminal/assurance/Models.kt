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
    FILESYSTEM_FORMAT,
    RAW_DEVICE_WRITE,
    SYSTEM_POWER_CHANGE,
    INFRASTRUCTURE_DESTROY,
    FORCE_OPERATION,
    UNRECOGNIZED_COMMAND,
    INVALID_REQUEST,
    OVERSIZED_COMMAND,
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
    val validUntil: Instant? = null,
    val policyId: String? = null,
    val policyVersion: String? = null,
    val assuranceBypassed: Boolean = false,
)

interface AssuranceProvider {
    val id: String
    val version: String
    suspend fun evaluate(request: PreflightRequest): AssuranceDecision
}
