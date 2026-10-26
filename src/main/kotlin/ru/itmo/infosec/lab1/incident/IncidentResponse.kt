package ru.itmo.infosec.lab1.incident

import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

data class IncidentResponse(
    val id: Long,
    val title: String,
    val description: String,
    val category: IncidentCategory,
    val severity: IncidentSeverity,
    val status: IncidentStatus,
    @get:JsonProperty("created_at")
    val createdAt: Instant,
    @get:JsonProperty("updated_at")
    val updatedAt: Instant,
)
