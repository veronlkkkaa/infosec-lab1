package ru.itmo.infosec.lab1.security

import jakarta.servlet.DispatcherType
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
import ru.itmo.infosec.lab1.error.JsonErrors

@Configuration
class SecurityConfig {
    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder(12)

    @Bean
    fun securityFilterChain(http: HttpSecurity, limiter: LoginLimiter): SecurityFilterChain {
        return http
            // Only explicit Bearer headers are accepted: no cookie, session or Basic authentication.
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .requestCache { it.disable() }
            .formLogin { it.disable() }
            .httpBasic { it.disable() }
            .logout { it.disable() }
            .authorizeHttpRequests {
                it.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                    .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/data").authenticated()
                    .requestMatchers(HttpMethod.POST, "/api/incidents").authenticated()
                    .requestMatchers(HttpMethod.PATCH, "/api/incidents/*/status").authenticated()
                    .anyRequest().denyAll()
            }
            .oauth2ResourceServer {
                it.jwt { }
                    .authenticationEntryPoint { _, response, _ ->
                        response.setHeader("WWW-Authenticate", "Bearer")
                        JsonErrors.write(response, 401, "unauthorized")
                    }
                    .accessDeniedHandler { _, response, _ -> JsonErrors.write(response, 403, "forbidden") }
            }
            .exceptionHandling {
                it.authenticationEntryPoint { _, response, _ ->
                    response.setHeader("WWW-Authenticate", "Bearer")
                    JsonErrors.write(response, 401, "unauthorized")
                }.accessDeniedHandler { _, response, _ -> JsonErrors.write(response, 403, "forbidden") }
            }
            .headers {
                it.contentSecurityPolicy { csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'") }
                    .referrerPolicy { policy -> policy.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER) }
            }
            .addFilterBefore(RequestGuardFilter(limiter), BearerTokenAuthenticationFilter::class.java)
            .build()
    }
}
