package ru.itmo.infosec.lab1.security

import java.util.ArrayDeque
import org.springframework.stereotype.Component

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
