package ru.itmo.infosec.lab1.security

import com.nimbusds.jose.jwk.source.ImmutableSecret
import com.nimbusds.jose.proc.SecurityContext
import java.time.Clock
import java.time.Duration
import java.util.Base64
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtIssuerValidator
import org.springframework.security.oauth2.jwt.JwtTimestampValidator
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import ru.itmo.infosec.lab1.auth.UserRepository

const val JWT_ISSUER = "lab1-secure-api"
const val JWT_AUDIENCE = "lab1-client"
const val JWT_LIFETIME_SECONDS = 900L

@Configuration
class JwtConfig {
    @Bean
    fun clock(): Clock = Clock.systemUTC()

    @Bean
    fun jwtKey(@Value("\${app.jwt.secret-base64}") encoded: String): SecretKey {
        val bytes = try {
            Base64.getDecoder().decode(encoded)
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("JWT_SECRET_BASE64 must be valid Base64")
        }
        require(bytes.size >= 32) { "JWT_SECRET_BASE64 must encode at least 32 random bytes" }
        return SecretKeySpec(bytes, "HmacSHA256")
    }

    @Bean
    fun jwtEncoder(key: SecretKey): JwtEncoder = NimbusJwtEncoder(ImmutableSecret<SecurityContext>(key))

    @Bean
    fun jwtDecoder(key: SecretKey, users: UserRepository, clock: Clock): JwtDecoder {
        val decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build()
        val timeValidator = JwtTimestampValidator(Duration.ZERO).apply { setClock(clock) }
        val requiredClaims = OAuth2TokenValidator<Jwt> { token ->
            val now = clock.instant()
            val id = token.subject?.toLongOrNull()
            val valid = id != null && id > 0 &&
                token.expiresAt?.isAfter(now) == true &&
                token.notBefore != null &&
                token.issuedAt?.let { !it.isAfter(now) } == true &&
                (token.audience?.contains(JWT_AUDIENCE) == true) && users.findById(id) != null
            if (valid) OAuth2TokenValidatorResult.success()
            else OAuth2TokenValidatorResult.failure(OAuth2Error("invalid_token", "Invalid claims", null))
        }
        decoder.setJwtValidator(
            DelegatingOAuth2TokenValidator(
                timeValidator, JwtIssuerValidator(JWT_ISSUER), requiredClaims,
            )
        )
        return decoder
    }
}
