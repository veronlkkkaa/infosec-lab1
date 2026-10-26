package ru.itmo.infosec.lab1.auth

import com.fasterxml.jackson.annotation.JsonProperty

data class TokenResponse(
    @get:JsonProperty("access_token")
    val accessToken: String,
    @get:JsonProperty("token_type")
    val tokenType: String = "Bearer",
    @get:JsonProperty("expires_in")
    val expiresIn: Long = 900,
)
