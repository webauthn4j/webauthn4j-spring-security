package net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.statement.AttestationStatement;

import javax.persistence.AttributeConverter;
import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * AttestationStatementConverter
 */
public class AttestationStatementConverter implements AttributeConverter<AttestationStatement, String> {

    private ObjectMapper jsonMapper = new Registry().getJsonMapper();

    @Override
    public String convertToDatabaseColumn(AttestationStatement attribute) {
        try {
            return jsonMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public AttestationStatement convertToEntityAttribute(String dbData) {
        try {
            return jsonMapper.readValue(dbData, AttestationStatement.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
