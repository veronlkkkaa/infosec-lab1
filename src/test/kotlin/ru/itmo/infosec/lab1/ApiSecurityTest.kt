package ru.itmo.infosec.lab1

import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import tools.jackson.databind.ObjectMapper

@SpringBootTest(
    properties = [
        "spring.datasource.url=jdbc:h2:mem:labtest;DB_CLOSE_DELAY=-1",
        "spring.datasource.username=sa", "spring.datasource.password=",
        "app.bootstrap.enabled=false",
    ]
)
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApiSecurityTest @Autowired constructor(
    private val mvc: MockMvc,
    private val json: ObjectMapper,
    private val jdbc: JdbcTemplate,
    private val users: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtEncoder: JwtEncoder,
    private val jwtDecoder: JwtDecoder,
    private val incidents: IncidentRepository,
) {
    private lateinit var passwordHash: String
    private var aliceId = 0L
    private var bobId = 0L
    private lateinit var address: String

    @BeforeAll
    fun prepareHash() {
        passwordHash = requireNotNull(passwordEncoder.encode(PASSWORD))
    }

    @BeforeEach
    fun prepareData() {
        jdbc.update("DELETE FROM incident")
        jdbc.update("DELETE FROM app_user")
        users.create("alice", passwordHash)
        users.create("bob", passwordHash)
        aliceId = requireNotNull(users.findByUsername("alice")).id
        bobId = requireNotNull(users.findByUsername("bob")).id
        address = "192.0.2.${NEXT_ADDRESS.incrementAndGet()}"
    }

    private fun request(builder: MockHttpServletRequestBuilder, token: String? = null): ResultActions {
        builder.with { it.remoteAddr = address; it }
        if (token != null) builder.header("Authorization", "Bearer $token")
        return mvc.perform(builder)
    }

    private fun postJson(path: String, body: Any, token: String? = null): ResultActions =
        request(
            post(path).servletPath(path).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsBytes(body)), token
        )

    private fun patchJson(path: String, body: Any, token: String? = null): ResultActions =
        request(
            patch(path).servletPath(path).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsBytes(body)), token
        )

    private fun incidentBody(): Map<String, Any?> = mapOf(
        "title" to "Suspicious email", "description" to "Unexpected attachment",
        "category" to "PHISHING", "severity" to "HIGH",
    )

    private fun createIncident(access: String): Long {
        val response = postJson("/api/incidents", incidentBody(), access)
            .andExpect(status().isCreated()).andExpect(jsonPath("$.status").value("NEW"))
            .andExpect(jsonPath("$.category").value("PHISHING"))
            .andExpect(jsonPath("$.severity").value("HIGH"))
            .andReturn().response.contentAsString
        return json.readTree(response)["id"].asLong()
    }

    private fun token(userId: Long = aliceId, change: (JwtClaimsSet.Builder) -> Unit = {}): String {
        val now = Instant.now()
        val claims = JwtClaimsSet.builder().subject(userId.toString()).issuer(JWT_ISSUER)
            .audience(listOf(JWT_AUDIENCE)).issuedAt(now).notBefore(now).expiresAt(now.plusSeconds(900))
        change(claims)
        return jwtEncoder.encode(
            JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),
                claims.build()
            )
        ).tokenValue
    }

    @Test
    fun `login returns a usable short lived signed JWT`() {
        val body = postJson("/auth/login", mapOf("username" to "alice", "password" to PASSWORD))
            .andExpect(status().isOk()).andExpect(jsonPath("$.expires_in").value(900))
            .andReturn().response.contentAsString
        val accessToken = json.readTree(body)["access_token"].asText()
        val decoded = jwtDecoder.decode(accessToken)
        assertThat(decoded.subject).isEqualTo(aliceId.toString())
        assertThat(requireNotNull(decoded.expiresAt).epochSecond - requireNotNull(decoded.issuedAt).epochSecond).isEqualTo(
            900
        )
        assertThat(decoded.claims).doesNotContainKeys("password", "password_hash")
        request(get("/api/data"), accessToken).andExpect(status().isOk())
    }

    @Test
    fun `wrong password and missing account return the same error`() {
        for (name in listOf("alice", "missing")) {
            postJson("/auth/login", mapOf("username" to name, "password" to "wrong"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("unauthorized"))
        }
    }

    @Test
    fun `SQL injection does not authenticate a user`() {
        postJson("/auth/login", mapOf("username" to "alice' OR 1=1 --", "password" to PASSWORD))
            .andExpect(status().isUnauthorized())
    }

    @Test
    fun `all protected methods reject missing JWT`() {
        patchJson("/api/incidents/1/status", mapOf("status" to "IN_PROGRESS"))
            .andExpect(status().isUnauthorized())
        request(get("/api/data")).andExpect(status().isUnauthorized())
        postJson("/api/incidents", incidentBody() + mapOf("title" to "A", "description" to "B"))
            .andExpect(status().isUnauthorized())
    }

    @Test
    fun `malformed and altered signatures are rejected`() {
        val parts = token().split('.')
        val first = if (parts[2][0] == 'A') 'B' else 'A'
        val changed = "${parts[0]}.${parts[1]}.$first${parts[2].substring(1)}"
        for (value in listOf("broken", "a.b.c", changed, "a".repeat(8193))) {
            request(get("/api/data"), value).andExpect(status().isUnauthorized())
        }
    }

    @Test
    fun `expired future and incorrect claims are rejected`() {
        val now = Instant.now()
        val values = listOf(
            token { it.issuedAt(now.minusSeconds(60)).notBefore(now.minusSeconds(60)).expiresAt(now.minusSeconds(1)) },
            token { it.notBefore(now.plusSeconds(60)) },
            token { it.issuedAt(now.plusSeconds(60)) },
            token { it.issuer("another-issuer") },
            token { it.audience(listOf("another-audience")) },
            token { it.subject("not-an-id") },
            token { it.subject(Long.MAX_VALUE.toString()) },
        )
        for (value in values) request(get("/api/data"), value).andExpect(status().isUnauthorized())
    }

    @Test
    fun `all required claims must be present`() {
        for (claim in listOf("sub", "exp", "iat", "nbf", "iss", "aud")) {
            val value = token { builder -> builder.claims { it.remove(claim) } }
            request(get("/api/data"), value).andExpect(status().isUnauthorized())
        }
    }

    @Test
    fun `unsigned JWT is rejected`() {
        fun encode(value: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray())
        val unsigned = "${encode("{\"alg\":\"none\"}")}.${encode("{\"sub\":\"$aliceId\"}")}."
        request(get("/api/data"), unsigned).andExpect(status().isUnauthorized())
    }

    @Test
    fun `user creates and reads an incident`() {
        postJson("/api/incidents", incidentBody() + mapOf("title" to "Hello", "description" to "World"), token())
            .andExpect(status().isCreated()).andExpect(jsonPath("$.title").value("Hello"))
        request(get("/api/data"), token()).andExpect(status().isOk())
            .andExpect(jsonPath("$.items.length()").value(1))
            .andExpect(jsonPath("$.items[0].description").value("World"))
    }

    @Test
    fun `another user cannot read or claim ownership of an incident`() {
        postJson("/api/incidents", incidentBody() + mapOf("title" to "Private", "description" to "Alice"), token())
            .andExpect(status().isCreated())
        request(get("/api/data"), token(bobId)).andExpect(status().isOk())
            .andExpect(jsonPath("$.items.length()").value(0))
        postJson(
            "/api/incidents",
            mapOf(
                "category" to "PHISHING",
                "severity" to "HIGH",
                "title" to "T",
                "description" to "C",
                "owner_id" to bobId
            ),
            token()
        )
            .andExpect(status().isBadRequest())
    }

    @Test
    fun `script input is encoded on creation and retrieval but stored raw`() {
        val value = "<script>alert(1)</script>"
        val escaped = "&lt;script&gt;alert(1)&lt;/script&gt;"
        postJson("/api/incidents", incidentBody() + mapOf("title" to value, "description" to value), token())
            .andExpect(status().isCreated()).andExpect(jsonPath("$.description").value(escaped))
        request(get("/api/data"), token()).andExpect(jsonPath("$.items[0].title").value(escaped))
        val id = jdbc.queryForObject("SELECT id FROM incident", Long::class.java)
        patchJson("/api/incidents/$id/status", mapOf("status" to "IN_PROGRESS"), token())
            .andExpect(status().isOk()).andExpect(jsonPath("$.description").value(escaped))
        assertThat(jdbc.queryForObject("SELECT description FROM incident", String::class.java)).isEqualTo(value)
    }

    @Test
    fun `SQL text in incidents cannot modify the schema`() {
        val value = "'); DROP TABLE app_user; --"
        postJson("/api/incidents", incidentBody() + mapOf("title" to "SQL", "description" to value), token())
            .andExpect(status().isCreated())
        assertThat(jdbc.queryForObject("SELECT count(*) FROM app_user", Int::class.java)).isEqualTo(2)
        assertThat(jdbc.queryForObject("SELECT description FROM incident", String::class.java)).isEqualTo(value)
    }

    @Test
    fun `invalid input is rejected before writing data`() {
        for (body in listOf(
            incidentBody() + mapOf("title" to " ", "description" to "C"),
            mapOf("category" to "PHISHING", "severity" to "HIGH", "title" to "x".repeat(121), "description" to "C"),
            mapOf("category" to "PHISHING", "severity" to "HIGH", "title" to "T", "description" to 123),
            mapOf("category" to "PHISHING", "severity" to "HIGH", "title" to "T"),
            mapOf("category" to "PHISHING", "severity" to "HIGH", "title" to "\u0000", "description" to "C"),
        )) postJson("/api/incidents", body, token()).andExpect(status().isBadRequest())
        request(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content("broken"))
            .andExpect(status().isBadRequest())
        request(post("/auth/login").contentType(MediaType.TEXT_PLAIN).content("text"))
            .andExpect(status().isUnsupportedMediaType())
        assertThat(jdbc.queryForObject("SELECT count(*) FROM incident", Int::class.java)).isZero()
    }

    @Test
    fun `numbers and booleans are not coerced into strings`() {
        for (value in listOf(123, 1.5, true)) {
            for (field in listOf("title", "description")) {
                val body = mutableMapOf<String, Any>(
                    "category" to "PHISHING",
                    "severity" to "HIGH",
                    "title" to "T",
                    "description" to "C"
                )
                body[field] = value
                postJson("/api/incidents", body, token()).andExpect { result ->
                    assertThat(result.response.status)
                        .describedAs("incident field %s with %s", field, value.javaClass.simpleName)
                        .isEqualTo(400)
                }
            }
            for (field in listOf("username", "password")) {
                val body = mutableMapOf<String, Any>("username" to "alice", "password" to PASSWORD)
                body[field] = value
                postJson("/auth/login", body).andExpect { result ->
                    assertThat(result.response.status)
                        .describedAs("login field %s with %s", field, value.javaClass.simpleName)
                        .isEqualTo(400)
                }
            }
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM incident", Int::class.java)).isZero()
    }

    @Test
    fun `another user cannot update an incident or distinguish it from an absent ID`() {
        val id = createIncident(token())
        for (target in listOf(id, Long.MAX_VALUE)) {
            patchJson("/api/incidents/$target/status", mapOf("status" to "IN_PROGRESS"), token(bobId))
                .andExpect(status().isNotFound()).andExpect(jsonPath("$.error").value("not_found"))
        }
        request(get("/api/data"), token()).andExpect(jsonPath("$.items[0].status").value("NEW"))
    }

    @Test
    fun `incident progresses through investigation and repeated status is idempotent`() {
        val path = "/api/incidents/${createIncident(token())}/status"
        val started = patchJson(path, mapOf("status" to "IN_PROGRESS"), token())
            .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("IN_PROGRESS"))
            .andReturn().response.contentAsString
        val repeated = patchJson(path, mapOf("status" to "IN_PROGRESS"), token())
            .andExpect(status().isOk()).andReturn().response.contentAsString
        assertThat(json.readTree(repeated)).isEqualTo(json.readTree(started))
        val closed = patchJson(path, mapOf("status" to "CLOSED"), token())
            .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("CLOSED"))
            .andReturn().response.contentAsString
        assertThat(json.readTree(closed)["created_at"]).isEqualTo(json.readTree(started)["created_at"])
        assertThat(Instant.parse(json.readTree(closed)["updated_at"].asText()))
            .isAfterOrEqualTo(Instant.parse(json.readTree(started)["updated_at"].asText()))
        request(get("/api/data"), token()).andExpect(jsonPath("$.items[0].status").value("CLOSED"))
    }

    @Test
    fun `workflow cannot skip investigation move backwards or reopen a closed incident`() {
        val path = "/api/incidents/${createIncident(token())}/status"
        patchJson(path, mapOf("status" to "CLOSED"), token()).andExpect(status().isConflict())
            .andExpect(jsonPath("$.error").value("invalid_status_transition"))
        patchJson(path, mapOf("status" to "IN_PROGRESS"), token()).andExpect(status().isOk())
        patchJson(path, mapOf("status" to "NEW"), token()).andExpect(status().isConflict())
        patchJson(path, mapOf("status" to "CLOSED"), token()).andExpect(status().isOk())
        for (value in listOf("NEW", "IN_PROGRESS")) {
            patchJson(path, mapOf("status" to value), token()).andExpect(status().isConflict())
        }
        request(get("/api/data"), token()).andExpect(jsonPath("$.items[0].status").value("CLOSED"))
    }

    @Test
    fun `enums require exact names and creation rejects client assigned state`() {
        for (field in listOf("category", "severity")) {
            postJson("/api/incidents", incidentBody() - field, token()).andExpect(status().isBadRequest())
            for (value in listOf(0, 1.5, true, null, "", "0", "unknown", emptyList<String>())) {
                postJson("/api/incidents", incidentBody() + (field to value), token())
                    .andExpect(status().isBadRequest())
            }
        }
        for ((field, value) in mapOf("category" to "phishing", "severity" to "high", "status" to "CLOSED")) {
            postJson("/api/incidents", incidentBody() + (field to value), token())
                .andExpect(status().isBadRequest())
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM incident", Int::class.java)).isZero()
    }

    @Test
    fun `status update rejects invalid types fields and identifiers`() {
        val path = "/api/incidents/${createIncident(token())}/status"
        for (value in listOf(0, 1.5, true, null, "", "0", "in_progress", "UNKNOWN", emptyList<String>())) {
            patchJson(path, mapOf("status" to value), token()).andExpect(status().isBadRequest())
        }
        patchJson(path, emptyMap<String, String>(), token()).andExpect(status().isBadRequest())
        patchJson(path, mapOf("status" to "IN_PROGRESS", "owner_id" to bobId), token())
            .andExpect(status().isBadRequest())
        for (id in listOf("0", "-1", "abc", "9223372036854775808")) {
            patchJson("/api/incidents/$id/status", mapOf("status" to "IN_PROGRESS"), token())
                .andExpect(status().isBadRequest())
        }
        request(get("/api/data"), token()).andExpect(jsonPath("$.items[0].status").value("NEW"))
    }

    @Test
    fun `stale status updates cannot overwrite a newer state`() {
        val id = createIncident(token())
        assertThat(incidents.compareAndSetStatus(aliceId, id, IncidentStatus.NEW, IncidentStatus.IN_PROGRESS)).isTrue()
        assertThat(incidents.compareAndSetStatus(aliceId, id, IncidentStatus.NEW, IncidentStatus.CLOSED)).isFalse()
        assertThat(
            incidents.compareAndSetStatus(
                bobId,
                id,
                IncidentStatus.IN_PROGRESS,
                IncidentStatus.CLOSED
            )
        ).isFalse()
        assertThat(requireNotNull(incidents.findOwnedById(aliceId, id)).status).isEqualTo(IncidentStatus.IN_PROGRESS)
    }

    @Test
    fun `list returns only the latest hundred owned incidents`() {
        repeat(101) { index ->
            incidents.create(aliceId, "Event $index", "Description", IncidentCategory.OTHER, IncidentSeverity.LOW)
        }
        incidents.create(bobId, "Bob event", "Description", IncidentCategory.OTHER, IncidentSeverity.LOW)
        request(get("/api/data"), token())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.items.length()").value(100))
            .andExpect(jsonPath("$.items[0].title").value("Event 100"))
            .andExpect(jsonPath("$.items[99].title").value("Event 1"))
    }

    @Test
    fun `large request body is rejected`() {
        request(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content("x".repeat(17_000)))
            .andExpect(status().isPayloadTooLarge())
    }

    @Test
    fun `login rate limiter rejects the eleventh request`() {
        repeat(10) { postJson("/auth/login", emptyMap<String, String>()).andExpect(status().isBadRequest()) }
        postJson("/auth/login", emptyMap<String, String>()).andExpect(status().isTooManyRequests())
            .andExpect(header().string("Retry-After", "60"))
    }

    @Test
    fun `bcrypt storage and its 72 byte limit are enforced`() {
        assertThat(passwordHash).startsWith("$" + "2a$" + "12$").isNotEqualTo(PASSWORD)
        assertThat(passwordEncoder.matches(PASSWORD, passwordHash)).isTrue()
        postJson("/auth/login", mapOf("username" to "alice", "password" to "a".repeat(73)))
            .andExpect(status().isBadRequest())
    }

    @Test
    fun `security headers apply to successful and rejected requests`() {
        for (value in listOf(null, token())) {
            request(get("/api/data"), value)
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().exists("Content-Security-Policy"))
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
        }
    }

    @Test
    fun `deleting a user invalidates their existing token`() {
        val issued = token()
        jdbc.update("DELETE FROM app_user WHERE id = ?", aliceId)
        request(get("/api/data"), issued).andExpect(status().isUnauthorized())
    }

    companion object {
        private fun randomString(): String =
            Base64.getEncoder().encodeToString(ByteArray(48).also { SecureRandom().nextBytes(it) })

        private val KEY = randomString()
        private val PASSWORD = randomString()
        private val NEXT_ADDRESS = AtomicInteger()

        @JvmStatic
        @DynamicPropertySource
        fun properties(registry: DynamicPropertyRegistry) {
            registry.add("app.jwt.secret-base64") { KEY }
        }
    }
}
