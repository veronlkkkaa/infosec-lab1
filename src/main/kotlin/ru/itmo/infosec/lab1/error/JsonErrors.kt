package ru.itmo.infosec.lab1.error

import jakarta.servlet.http.HttpServletResponse
import tools.jackson.databind.json.JsonMapper

object JsonErrors {
    private val mapper = JsonMapper.builder().build()

    // All callers pass fixed internal error identifiers, never submitted text.
    fun write(response: HttpServletResponse, status: Int, code: String) {
        response.status = status
        response.contentType = "application/json"
        response.characterEncoding = "UTF-8"
        response.setHeader("Cache-Control", "no-store")
        mapper.writeValue(response.writer, ApiError(code))
    }
}
