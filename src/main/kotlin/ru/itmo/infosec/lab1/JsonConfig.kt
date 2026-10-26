package ru.itmo.infosec.lab1

import tools.jackson.databind.cfg.CoercionAction
import tools.jackson.databind.cfg.CoercionInputShape
import tools.jackson.databind.type.LogicalType
import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class JsonConfig {
    @Bean
    fun strictJsonStrings(): JsonMapperBuilderCustomizer =
        JsonMapperBuilderCustomizer { builder ->
            // Explicitly reject number/boolean-to-String coercion at the API boundary.
            builder.withCoercionConfig(LogicalType.Textual) { config ->
                config.setCoercion(CoercionInputShape.Integer, CoercionAction.Fail)
                    .setCoercion(CoercionInputShape.Float, CoercionAction.Fail)
                    .setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail)
            }
        }
}
