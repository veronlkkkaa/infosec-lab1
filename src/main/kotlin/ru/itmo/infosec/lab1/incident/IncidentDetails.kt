package ru.itmo.infosec.lab1.incident

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
