package ru.itmo.infosec.lab1.incident

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

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
