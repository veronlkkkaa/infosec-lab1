package ru.itmo.infosec.lab1.security

import jakarta.servlet.FilterChain
import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import jakarta.servlet.http.HttpServletResponse
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import org.springframework.web.filter.OncePerRequestFilter
import ru.itmo.infosec.lab1.error.JsonErrors

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
