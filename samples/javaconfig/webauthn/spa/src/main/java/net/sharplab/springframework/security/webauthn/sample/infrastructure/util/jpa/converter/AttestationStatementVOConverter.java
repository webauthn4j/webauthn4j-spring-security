package net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.registry.Registry;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AttestationStatementVO;

import javax.persistence.AttributeConverter;
import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * AttestationStatementVOConverter
 */
public class AttestationStatementVOConverter implements AttributeConverter<AttestationStatementVO, String> {

    private ObjectMapper jsonMapper = new Registry().getJsonMapper();

    @Override
    public String convertToDatabaseColumn(AttestationStatementVO attribute) {
        try {
            return jsonMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public AttestationStatementVO convertToEntityAttribute(String dbData) {
        try {
            return jsonMapper.readValue(dbData, AttestationStatementVO.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
