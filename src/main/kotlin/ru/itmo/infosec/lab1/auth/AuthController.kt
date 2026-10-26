package ru.itmo.infosec.lab1.auth

import jakarta.validation.Valid
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class AuthController(private val auth: AuthService) {
    @PostMapping("/auth/login", consumes = ["application/json"], produces = ["application/json"])
    fun login(@Valid @RequestBody body: LoginRequest): TokenResponse = auth.login(body)
}
