package ru.itmo.infosec.lab1.incident

import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.util.HtmlUtils
import ru.itmo.infosec.lab1.error.ApiException

@RestController
class IncidentController(private val incidents: IncidentService) {
    @GetMapping("/api/data", produces = ["application/json"])
    fun listIncidents(@AuthenticationPrincipal jwt: Jwt): IncidentList =
        IncidentList(incidents.listOwned(jwt.ownerId()).map { it.toResponse() })

    @PostMapping("/api/incidents", consumes = ["application/json"], produces = ["application/json"])
    @ResponseStatus(HttpStatus.CREATED)
    fun createIncident(
        @AuthenticationPrincipal jwt: Jwt,
        @Valid @RequestBody body: CreateIncidentRequest,
    ): IncidentResponse = incidents.create(
        ownerId = jwt.ownerId(),
        details = IncidentDetails(
            title = body.title,
            description = body.description,
            category = body.category,
            severity = body.severity,
        ),
    ).toResponse()

    @PatchMapping("/api/incidents/{id}/status", consumes = ["application/json"], produces = ["application/json"])
    fun updateIncidentStatus(
        @AuthenticationPrincipal jwt: Jwt,
        @PathVariable("id") id: Long,
        @RequestBody body: UpdateIncidentStatusRequest,
    ): IncidentResponse = incidents.updateStatus(jwt.ownerId(), id, body.status).toResponse()

    private fun Jwt.ownerId(): Long = subject?.toLongOrNull()?.takeIf { it > 0 }
        ?: throw ApiException(HttpStatus.UNAUTHORIZED, "unauthorized")

    private fun IncidentRecord.toResponse() = IncidentResponse(
        id = id,
        title = HtmlUtils.htmlEscape(title, "UTF-8"),
        description = HtmlUtils.htmlEscape(description, "UTF-8"),
        category = category,
        severity = severity,
        status = status,
        createdAt = createdAt,
        updatedAt = updatedAt,
    )
}
