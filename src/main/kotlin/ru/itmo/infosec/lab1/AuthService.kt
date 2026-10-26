package ru.itmo.infosec.lab1

import java.security.SecureRandom
import java.time.Clock
import java.util.Base64
import org.springframework.http.HttpStatus
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.stereotype.Service

@Service
class AuthService(
    private val users: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtEncoder: JwtEncoder,
    private val clock: Clock,
) {
    private val dummyHash = passwordEncoder.encode(
        Base64.getEncoder().encodeToString(
            ByteArray(32).also { SecureRandom().nextBytes(it) },
        )
    )

    fun login(body: LoginRequest): TokenResponse {
        if (!TextRules.valid(body.username) || !TextRules.passwordFitsBcrypt(body.password)) {
            throw ApiException(HttpStatus.BAD_REQUEST, "invalid_request")
        }
        val user = users.findByUsername(body.username)
        val matches = passwordEncoder.matches(body.password, user?.passwordHash ?: dummyHash)
        if (user == null || !matches) throw ApiException(HttpStatus.UNAUTHORIZED, "unauthorized")
        val now = clock.instant()
        val claims = JwtClaimsSet.builder()
            .issuer(JWT_ISSUER).audience(listOf(JWT_AUDIENCE)).subject(user.id.toString())
            .issuedAt(now).notBefore(now).expiresAt(now.plusSeconds(JWT_LIFETIME_SECONDS)).build()
        val header = JwsHeader.with(MacAlgorithm.HS256).build()
        return TokenResponse(jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).tokenValue)
    }
}
