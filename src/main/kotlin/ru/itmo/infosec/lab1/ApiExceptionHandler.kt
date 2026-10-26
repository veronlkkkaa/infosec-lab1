package ru.itmo.infosec.lab1

import org.slf4j.LoggerFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatusCode
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.context.request.WebRequest
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler

@RestControllerAdvice
class ApiExceptionHandler : ResponseEntityExceptionHandler() {
    private val log = LoggerFactory.getLogger(ApiExceptionHandler::class.java)

    @ExceptionHandler(ApiException::class)
    fun apiError(error: ApiException): ResponseEntity<ApiError> {
        val headers = HttpHeaders()
        if (error.status.value() == 401) headers.set("WWW-Authenticate", "Bearer")
        return ResponseEntity.status(error.status).headers(headers).body(ApiError(error.code))
    }

    override fun handleExceptionInternal(
        ex: Exception, body: Any?, headers: HttpHeaders, statusCode: HttpStatusCode, request: WebRequest,
    ): ResponseEntity<Any> {
        val code = when (statusCode.value()) {
            400 -> "invalid_request"
            404 -> "not_found"
            405 -> "method_not_allowed"
            413 -> "request_too_large"
            415 -> "json_required"
            else -> "request_failed"
        }
        return ResponseEntity.status(statusCode).headers(headers).body(ApiError(code))
    }

    @ExceptionHandler(Exception::class)
    fun unexpectedError(): ResponseEntity<ApiError> {
        // Do not log submitted bodies, passwords, JWTs or JDBC parameter values.
        log.error("Unhandled API error; inspect server configuration")
        return ResponseEntity.internalServerError().body(ApiError("internal_server_error"))
    }
}
