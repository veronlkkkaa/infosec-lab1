package ru.itmo.infosec.lab1.incident

import java.time.Instant

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
