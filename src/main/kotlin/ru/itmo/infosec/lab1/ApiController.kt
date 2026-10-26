package ru.itmo.infosec.lab1

import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.*
import org.springframework.web.util.HtmlUtils

@RestController
class ApiController(private val auth: AuthService, private val notes: NoteRepository) {
    @PostMapping("/auth/login", consumes = ["application/json"], produces = ["application/json"])
    fun login(@Valid @RequestBody body: LoginRequest): TokenResponse = auth.login(body)

    @GetMapping("/api/data", produces = ["application/json"])
    fun listNotes(@AuthenticationPrincipal jwt: Jwt): NoteList =
        NoteList(notes.findOwned(jwt.ownerId()).map { it.toResponse() })

    @PostMapping("/api/notes", consumes = ["application/json"], produces = ["application/json"])
    @ResponseStatus(HttpStatus.CREATED)
    fun createNote(@AuthenticationPrincipal jwt: Jwt, @Valid @RequestBody body: CreateNoteRequest): NoteResponse {
        if (!TextRules.valid(body.title) || !TextRules.valid(body.content)) {
            throw ApiException(HttpStatus.BAD_REQUEST, "invalid_request")
        }
        return notes.create(jwt.ownerId(), body.title, body.content).toResponse()
    }

    private fun Jwt.ownerId(): Long = subject?.toLongOrNull()?.takeIf { it > 0 }
        ?: throw ApiException(HttpStatus.UNAUTHORIZED, "unauthorized")

    private fun NoteRecord.toResponse() = NoteResponse(
        id, HtmlUtils.htmlEscape(title, "UTF-8"), HtmlUtils.htmlEscape(content, "UTF-8"), createdAt,
    )
}
