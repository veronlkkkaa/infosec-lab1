package ru.itmo.infosec.lab1.validation

object TextRules {
    fun valid(value: String): Boolean = value.isNotBlank() && '\u0000' !in value &&
        Charsets.UTF_8.newEncoder().canEncode(value)

    fun passwordFitsBcrypt(value: String): Boolean = valid(value) &&
        value.toByteArray(Charsets.UTF_8).size <= 72
}
