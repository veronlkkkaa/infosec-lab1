package ru.itmo.infosec.lab1

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.http.HttpStatus

// A regular class avoids a generated toString() containing the submitted password.
class LoginRequest(
    @field:NotBlank
    @field:Size(max = 64)
    val username: String,
    @field:NotBlank
    @field:Size(max = 128)
    val password: String,
)

data class TokenResponse(
    @get:JsonProperty("access_token")
    val accessToken: String,
    @get:JsonProperty("token_type")
    val tokenType: String = "Bearer",
    @get:JsonProperty("expires_in")
    val expiresIn: Long = 900,
)

data class ApiError(val error: String)
class ApiException(val status: HttpStatus, val code: String) : RuntimeException(code)

object TextRules {
    fun valid(value: String): Boolean = value.isNotBlank() && '\u0000' !in value &&
        Charsets.UTF_8.newEncoder().canEncode(value)

    fun passwordFitsBcrypt(value: String): Boolean = valid(value) &&
        value.toByteArray(Charsets.UTF_8).size <= 72
}
