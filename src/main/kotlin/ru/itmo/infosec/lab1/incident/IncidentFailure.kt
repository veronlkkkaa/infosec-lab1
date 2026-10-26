package ru.itmo.infosec.lab1.incident

enum class IncidentFailure(val code: String) {
    INVALID_DATA("invalid_request"),
    NOT_FOUND("not_found"),
    INVALID_TRANSITION("invalid_status_transition"),
    CONCURRENT_CHANGE("incident_changed"),
}
