package ru.itmo.infosec.lab1

import jakarta.servlet.FilterChain
import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import jakarta.servlet.http.HttpServletResponse
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.util.ArrayDeque
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import tools.jackson.databind.json.JsonMapper

object JsonErrors {
    private val mapper = JsonMapper.builder().build()

    // All callers pass fixed internal error identifiers, never submitted text.
    fun write(response: HttpServletResponse, status: Int, code: String) {
        response.status = status
        response.contentType = "application/json"
        response.characterEncoding = "UTF-8"
        response.setHeader("Cache-Control", "no-store")
        mapper.writeValue(response.writer, ApiError(code))
    }
}

@Component
class LoginLimiter {
    private val attempts = mutableMapOf<String, ArrayDeque<Long>>()

    @Synchronized
    fun allow(address: String): Boolean {
        val now = System.nanoTime()
        val cutoff = now - 60_000_000_000L
        val entries = attempts.entries.iterator()
        while (entries.hasNext()) {
            val timestamps = entries.next().value
            while (timestamps.isNotEmpty() && timestamps.peekFirst() <= cutoff) timestamps.removeFirst()
            if (timestamps.isEmpty()) entries.remove()
        }
        if (address !in attempts && attempts.size >= 4096) return false
        val timestamps = attempts.getOrPut(address) { ArrayDeque() }
        if (timestamps.size >= 10) return false
        timestamps.addLast(now)
        return true
    }
}

// Instantiated only inside SecurityFilterChain, not registered as a second servlet filter.
class RequestGuardFilter(private val limiter: LoginLimiter) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        if (request.method == "POST" && request.servletPath == "/auth/login" && !limiter.allow(request.remoteAddr)) {
            response.setHeader("Retry-After", "60")
            JsonErrors.write(response, 429, "too_many_requests")
            return
        }
        if ((request.getHeader("Authorization")?.length ?: 0) > 8192) {
            response.setHeader("WWW-Authenticate", "Bearer")
            JsonErrors.write(response, 401, "unauthorized")
            return
        }
        if (request.contentLengthLong > MAX_BODY_BYTES) {
            JsonErrors.write(response, 413, "request_too_large")
            return
        }
        // Also bound chunked bodies with unknown Content-Length.
        val bytes = request.inputStream.readNBytes(MAX_BODY_BYTES + 1)
        if (bytes.size > MAX_BODY_BYTES) {
            JsonErrors.write(response, 413, "request_too_large")
            return
        }
        chain.doFilter(CachedBodyRequest(request, bytes), response)
    }

    companion object {
        private const val MAX_BODY_BYTES = 16 * 1024
    }
}

private class CachedBodyRequest(
    request: HttpServletRequest,
    private val bytes: ByteArray,
) : HttpServletRequestWrapper(request) {
    override fun getContentLength(): Int = bytes.size
    override fun getContentLengthLong(): Long = bytes.size.toLong()
    override fun getInputStream(): ServletInputStream {
        val input = ByteArrayInputStream(bytes)
        return object : ServletInputStream() {
            override fun read(): Int = input.read()
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int = input.read(buffer, offset, length)
            override fun isFinished(): Boolean = input.available() == 0
            override fun isReady(): Boolean = true
            override fun setReadListener(listener: ReadListener?) {
                throw UnsupportedOperationException("This API uses synchronous request processing")
            }
        }
    }

    override fun getReader(): BufferedReader = BufferedReader(InputStreamReader(inputStream, Charsets.UTF_8))
}
