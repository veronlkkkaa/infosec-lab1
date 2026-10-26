package ru.itmo.infosec.lab1

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import java.time.Instant

data class CreateIncidentRequest(
    @field:NotBlank
    @field:Size(max = IncidentDetails.MAX_TITLE_LENGTH)
    val title: String,
    @field:NotBlank
    @field:Size(max = IncidentDetails.MAX_DESCRIPTION_LENGTH)
    val description: String,
    val category: IncidentCategory,
    val severity: IncidentSeverity,
)

data class UpdateIncidentStatusRequest(val status: IncidentStatus)

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

data class IncidentList(val items: List<IncidentResponse>)
