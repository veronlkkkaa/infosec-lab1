package ru.itmo.infosec.lab1.incident

import java.time.OffsetDateTime
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import org.springframework.jdbc.support.GeneratedKeyHolder
import org.springframework.stereotype.Repository

@Repository
class IncidentRepository(private val jdbc: JdbcTemplate) {
    private val mapper = RowMapper<IncidentRecord> { rs, _ ->
        IncidentRecord(
            id = rs.getLong("id"),
            title = rs.getString("title"),
            description = rs.getString("description"),
            category = IncidentCategory.valueOf(rs.getString("category")),
            severity = IncidentSeverity.valueOf(rs.getString("severity")),
            status = IncidentStatus.valueOf(rs.getString("status")),
            createdAt = rs.getObject("created_at", OffsetDateTime::class.java).toInstant(),
            updatedAt = rs.getObject("updated_at", OffsetDateTime::class.java).toInstant(),
        )
    }

    fun findOwned(ownerId: Long): List<IncidentRecord> = jdbc.query(
        """
        SELECT id, title, description, category, severity, status, created_at, updated_at
        FROM incident
        WHERE owner_id = ?
        ORDER BY id DESC
        LIMIT ?
        """.trimIndent(),
        mapper, ownerId, MAX_LIST_SIZE,
    )

    fun findOwnedById(ownerId: Long, id: Long): IncidentRecord? = jdbc.query(
        """
        SELECT id, title, description, category, severity, status, created_at, updated_at
        FROM incident
        WHERE id = ? AND owner_id = ?
        """.trimIndent(),
        mapper, id, ownerId,
    ).firstOrNull()

    fun create(
        ownerId: Long,
        title: String,
        description: String,
        category: IncidentCategory,
        severity: IncidentSeverity,
    ): IncidentRecord {
        val key = GeneratedKeyHolder()
        jdbc.update({ connection ->
            connection.prepareStatement(
                """
                INSERT INTO incident (owner_id, title, description, category, severity)
                VALUES (?, ?, ?, ?, ?)
                """.trimIndent(),
                arrayOf("ID"),
            ).apply {
                setLong(1, ownerId)
                setString(2, title)
                setString(3, description)
                setString(4, category.name)
                setString(5, severity.name)
            }
        }, key)
        val id = requireNotNull(key.key).toLong()
        return requireNotNull(findOwnedById(ownerId, id))
    }

    fun compareAndSetStatus(ownerId: Long, id: Long, current: IncidentStatus, next: IncidentStatus): Boolean =
        jdbc.update(
            """
            UPDATE incident
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND owner_id = ? AND status = ?
            """.trimIndent(),
            next.name, id, ownerId, current.name,
        ) == 1

    private companion object {
        const val MAX_LIST_SIZE = 100
    }
}
