package ru.itmo.infosec.lab1.incident

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import ru.itmo.infosec.lab1.validation.TextRules

@Service
class IncidentService(private val incidents: IncidentRepository) {
    fun listOwned(ownerId: Long): List<IncidentRecord> = incidents.findOwned(ownerId)

    @Transactional
    fun create(ownerId: Long, details: IncidentDetails): IncidentRecord {
        if (!TextRules.valid(details.title) || !TextRules.valid(details.description) ||
            details.title.length > IncidentDetails.MAX_TITLE_LENGTH ||
            details.description.length > IncidentDetails.MAX_DESCRIPTION_LENGTH
        ) {
            throw IncidentException(IncidentFailure.INVALID_DATA)
        }
        return incidents.create(
            ownerId = ownerId,
            title = details.title,
            description = details.description,
            category = details.category,
            severity = details.severity,
        )
    }

    @Transactional
    fun updateStatus(ownerId: Long, id: Long, next: IncidentStatus): IncidentRecord {
        if (id <= 0) throw IncidentException(IncidentFailure.INVALID_DATA)
        // Identical errors for foreign and absent IDs avoid disclosing another user's records.
        val current = incidents.findOwnedById(ownerId, id)
            ?: throw IncidentException(IncidentFailure.NOT_FOUND)
        if (!current.status.canTransitionTo(next)) {
            throw IncidentException(IncidentFailure.INVALID_TRANSITION)
        }
        if (current.status == next) return current
        // The update compares the previous state to avoid overwriting a concurrent transition.
        if (!incidents.compareAndSetStatus(ownerId, id, current.status, next)) {
            throw IncidentException(IncidentFailure.CONCURRENT_CHANGE)
        }
        return requireNotNull(incidents.findOwnedById(ownerId, id))
    }
}
