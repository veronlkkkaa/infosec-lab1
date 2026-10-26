package ru.itmo.infosec.lab1.incident

class IncidentException(val failure: IncidentFailure) : RuntimeException(failure.code)
