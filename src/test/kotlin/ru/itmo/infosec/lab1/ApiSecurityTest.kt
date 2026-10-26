package ru.itmo.infosec.lab1

import tools.jackson.databind.ObjectMapper
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jwt.*
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger

@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:labtest;DB_CLOSE_DELAY=-1",
    "spring.datasource.username=sa", "spring.datasource.password=",
    "app.bootstrap.enabled=false",
])
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
) {
    private lateinit var passwordHash: String
    private var aliceId = 0L
    private var bobId = 0L
    private lateinit var address: String

    @BeforeAll
    fun prepareHash() { passwordHash = requireNotNull(passwordEncoder.encode(PASSWORD)) }

    @BeforeEach
    fun prepareData() {
        jdbc.update("DELETE FROM note")
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
        request(post(path).servletPath(path).contentType(MediaType.APPLICATION_JSON)
            .content(json.writeValueAsBytes(body)), token)

    private fun token(userId: Long = aliceId, change: (JwtClaimsSet.Builder) -> Unit = {}): String {
        val now = Instant.now()
        val claims = JwtClaimsSet.builder().subject(userId.toString()).issuer(JWT_ISSUER)
            .audience(listOf(JWT_AUDIENCE)).issuedAt(now).notBefore(now).expiresAt(now.plusSeconds(900))
        change(claims)
        return jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims.build())).tokenValue
    }

    @Test
    fun `login returns a usable short lived signed JWT`() {
        val body = postJson("/auth/login", mapOf("username" to "alice", "password" to PASSWORD))
            .andExpect(status().isOk()).andExpect(jsonPath("$.expires_in").value(900))
            .andReturn().response.contentAsString
        val accessToken = json.readTree(body)["access_token"].asText()
        val decoded = jwtDecoder.decode(accessToken)
        assertThat(decoded.subject).isEqualTo(aliceId.toString())
        assertThat(decoded.expiresAt!!.epochSecond - decoded.issuedAt!!.epochSecond).isEqualTo(900)
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
    fun `both protected methods reject missing JWT`() {
        request(get("/api/data")).andExpect(status().isUnauthorized())
        postJson("/api/notes", mapOf("title" to "A", "content" to "B"))
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
    fun `user creates and reads a note`() {
        postJson("/api/notes", mapOf("title" to "Hello", "content" to "World"), token())
            .andExpect(status().isCreated()).andExpect(jsonPath("$.title").value("Hello"))
        request(get("/api/data"), token()).andExpect(status().isOk())
            .andExpect(jsonPath("$.items.length()").value(1)).andExpect(jsonPath("$.items[0].content").value("World"))
    }

    @Test
    fun `another user cannot read or claim ownership of a note`() {
        postJson("/api/notes", mapOf("title" to "Private", "content" to "Alice"), token())
            .andExpect(status().isCreated())
        request(get("/api/data"), token(bobId)).andExpect(status().isOk())
            .andExpect(jsonPath("$.items.length()").value(0))
        postJson("/api/notes", mapOf("title" to "T", "content" to "C", "owner_id" to bobId), token())
            .andExpect(status().isBadRequest())
    }

    @Test
    fun `script input is encoded on creation and retrieval but stored raw`() {
        val value = "<script>alert(1)</script>"
        val escaped = "&lt;script&gt;alert(1)&lt;/script&gt;"
        postJson("/api/notes", mapOf("title" to value, "content" to value), token())
            .andExpect(status().isCreated()).andExpect(jsonPath("$.content").value(escaped))
        request(get("/api/data"), token()).andExpect(jsonPath("$.items[0].title").value(escaped))
        assertThat(jdbc.queryForObject("SELECT content FROM note", String::class.java)).isEqualTo(value)
    }

    @Test
    fun `SQL text in notes cannot modify the schema`() {
        val value = "'); DROP TABLE app_user; --"
        postJson("/api/notes", mapOf("title" to "SQL", "content" to value), token())
            .andExpect(status().isCreated())
        assertThat(jdbc.queryForObject("SELECT count(*) FROM app_user", Int::class.java)).isEqualTo(2)
        assertThat(jdbc.queryForObject("SELECT content FROM note", String::class.java)).isEqualTo(value)
    }

    @Test
    fun `invalid input is rejected before writing data`() {
        for (body in listOf(
            mapOf("title" to " ", "content" to "C"),
            mapOf("title" to "x".repeat(121), "content" to "C"),
            mapOf("title" to "T", "content" to 123),
            mapOf("title" to "T"), mapOf("title" to "\u0000", "content" to "C"),
        )) postJson("/api/notes", body, token()).andExpect(status().isBadRequest())
        request(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content("broken"))
            .andExpect(status().isBadRequest())
        request(post("/auth/login").contentType(MediaType.TEXT_PLAIN).content("text"))
            .andExpect(status().isUnsupportedMediaType())
        assertThat(jdbc.queryForObject("SELECT count(*) FROM note", Int::class.java)).isZero()
    }

    @Test
    fun `numbers and booleans are not coerced into strings`() {
        for (value in listOf(123, 1.5, true)) {
            for (field in listOf("title", "content")) {
                val body = mutableMapOf<String, Any>("title" to "T", "content" to "C")
                body[field] = value
                postJson("/api/notes", body, token()).andExpect { result ->
                    assertThat(result.response.status)
                        .describedAs("notes field %s with %s", field, value.javaClass.simpleName)
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
        assertThat(jdbc.queryForObject("SELECT count(*) FROM note", Int::class.java)).isZero()
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
        private fun randomString(): String = Base64.getEncoder().encodeToString(ByteArray(48).also { SecureRandom().nextBytes(it) })
        private val KEY = randomString()
        private val PASSWORD = randomString()
        private val NEXT_ADDRESS = AtomicInteger()

        @JvmStatic
        @DynamicPropertySource
        fun properties(registry: DynamicPropertyRegistry) { registry.add("app.jwt.secret-base64") { KEY } }
    }
}
