package net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.authenticator.CredentialPublicKey;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.io.IOException;
import java.io.UncheckedIOException;

@Converter
public class CredentialPublicKeyConverter implements AttributeConverter<CredentialPublicKey, String> {

    private ObjectMapper jsonMapper = new Registry().getJsonMapper();

    @Override
    public String convertToDatabaseColumn(CredentialPublicKey attribute) {
        try {
            return jsonMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public CredentialPublicKey convertToEntityAttribute(String dbData) {
        try {
            return jsonMapper.readValue(dbData, CredentialPublicKey.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
