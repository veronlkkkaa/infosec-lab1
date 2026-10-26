package ru.itmo.infosec.lab1.auth

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import org.springframework.stereotype.Repository

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
