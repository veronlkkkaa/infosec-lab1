package ru.itmo.infosec.lab1.auth

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import ru.itmo.infosec.lab1.validation.TextRules

@Component
@DependsOnDatabaseInitialization
@ConditionalOnProperty(prefix = "app.bootstrap", name = ["enabled"], havingValue = "true", matchIfMissing = true)
class BootstrapUsers(
    private val users: UserRepository,
    private val encoder: PasswordEncoder,
    @param:Value("\${app.bootstrap.username}") private val username: String,
    @param:Value("\${app.bootstrap.password}") private val password: String,
    @param:Value("\${app.bootstrap.second-username}") private val secondUsername: String,
    @param:Value("\${app.bootstrap.second-password}") private val secondPassword: String,
) : ApplicationRunner {
    @Transactional
    override fun run(args: ApplicationArguments) {
        createIfMissing(username, password)
        if (secondPassword.isNotEmpty()) {
            require(secondUsername != username) { "The second username must be different" }
            createIfMissing(secondUsername, secondPassword)
        }
    }

    private fun createIfMissing(name: String, suppliedPassword: String) {
        require(Regex("[A-Za-z0-9_.-]{3,64}").matches(name)) {
            "Username must contain 3-64 ASCII letters, digits, _, . or -"
        }
        if (users.findByUsername(name) != null) return
        require(suppliedPassword.length >= 15 && TextRules.passwordFitsBcrypt(suppliedPassword)) {
            "Set a password of at least 15 characters and at most 72 UTF-8 bytes in LAB_PASSWORD / LAB_SECOND_PASSWORD"
        }
        users.create(name, requireNotNull(encoder.encode(suppliedPassword)))
    }
}
