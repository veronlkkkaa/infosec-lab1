package ru.itmo.infosec.lab1.auth

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

// A regular class avoids a generated toString() containing the submitted password.
class LoginRequest(
    @field:NotBlank
    @field:Size(max = 64)
    val username: String,
    @field:NotBlank
    @field:Size(max = 128)
    val password: String,
)
