package ru.itmo.infosec.lab1

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import org.springframework.jdbc.support.GeneratedKeyHolder
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.time.OffsetDateTime

class UserRecord(val id: Long, val username: String, val passwordHash: String)
data class NoteRecord(val id: Long, val title: String, val content: String, val createdAt: Instant)

@Repository
class UserRepository(private val jdbc: JdbcTemplate) {
    private val mapper = RowMapper<UserRecord> { rs, _ ->
        UserRecord(rs.getLong("id"), rs.getString("username"), rs.getString("password_hash"))
    }

    fun findByUsername(username: String): UserRecord? = jdbc.query(
        "SELECT id, username, password_hash FROM app_user WHERE username = ?", mapper, username,
    ).firstOrNull()

    fun findById(id: Long): UserRecord? = jdbc.query(
        "SELECT id, username, password_hash FROM app_user WHERE id = ?", mapper, id,
    ).firstOrNull()

    fun create(username: String, passwordHash: String) {
        jdbc.update("INSERT INTO app_user (username, password_hash) VALUES (?, ?)", username, passwordHash)
    }
}

@Repository
class NoteRepository(private val jdbc: JdbcTemplate) {
    private val mapper = RowMapper<NoteRecord> { rs, _ ->
        NoteRecord(rs.getLong("id"), rs.getString("title"), rs.getString("content"),
            rs.getObject("created_at", OffsetDateTime::class.java).toInstant())
    }

    fun findOwned(ownerId: Long): List<NoteRecord> = jdbc.query(
        "SELECT id, title, content, created_at FROM note WHERE owner_id = ? ORDER BY id DESC LIMIT 100",
        mapper, ownerId,
    )

    @Transactional
    fun create(ownerId: Long, title: String, content: String): NoteRecord {
        val key = GeneratedKeyHolder()
        jdbc.update({ connection ->
            connection.prepareStatement(
                "INSERT INTO note (owner_id, title, content) VALUES (?, ?, ?)", arrayOf("ID"),
            ).apply {
                setLong(1, ownerId)
                setString(2, title)
                setString(3, content)
            }
        }, key)
        val id = requireNotNull(key.key).toLong()
        return jdbc.query(
            "SELECT id, title, content, created_at FROM note WHERE id = ? AND owner_id = ?",
            mapper, id, ownerId,
        ).single()
    }
}
