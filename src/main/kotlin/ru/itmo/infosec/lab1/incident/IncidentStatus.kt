package ru.itmo.infosec.lab1.incident

enum class IncidentStatus {
    NEW, IN_PROGRESS, CLOSED;

    fun canTransitionTo(next: IncidentStatus): Boolean = next == this || when (this) {
        NEW -> next == IN_PROGRESS
        IN_PROGRESS -> next == CLOSED
        CLOSED -> false
    }
}
