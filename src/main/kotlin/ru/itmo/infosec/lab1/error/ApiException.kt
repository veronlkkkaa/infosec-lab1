package ru.itmo.infosec.lab1.error

import org.springframework.http.HttpStatus

class ApiException(val status: HttpStatus, val code: String) : RuntimeException(code)
