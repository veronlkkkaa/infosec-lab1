package ru.itmo.infosec.lab1

import java.time.Instant

enum class IncidentCategory { PHISHING, MALWARE, UNAUTHORIZED_ACCESS, DATA_LEAK, OTHER }
enum class IncidentSeverity { LOW, MEDIUM, HIGH, CRITICAL }
enum class IncidentStatus {
    NEW, IN_PROGRESS, CLOSED;

    fun canTransitionTo(next: IncidentStatus): Boolean = next == this || when (this) {
        NEW -> next == IN_PROGRESS
        IN_PROGRESS -> next == CLOSED
        CLOSED -> false
    }
}

data class IncidentRecord(
    val id: Long,
    val title: String,
    val description: String,
    val category: IncidentCategory,
    val severity: IncidentSeverity,
    val status: IncidentStatus,
    val createdAt: Instant,
    val updatedAt: Instant,
)

data class IncidentDetails(
    val title: String,
    val description: String,
    val category: IncidentCategory,
    val severity: IncidentSeverity,
) {
    companion object {
        const val MAX_TITLE_LENGTH = 120
        const val MAX_DESCRIPTION_LENGTH = 2000
    }
}

enum class IncidentFailure(val code: String) {
    INVALID_DATA("invalid_request"),
    NOT_FOUND("not_found"),
    INVALID_TRANSITION("invalid_status_transition"),
    CONCURRENT_CHANGE("incident_changed"),
}

class IncidentException(val failure: IncidentFailure) : RuntimeException(failure.code)
