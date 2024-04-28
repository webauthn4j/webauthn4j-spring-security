package com.webauthn4j.springframework.security.webauthn.sample.infrastructure.util.jpa.converter;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.client.CollectedClientData;
import jakarta.persistence.AttributeConverter;

public class CollectedClientDataConverter implements AttributeConverter<CollectedClientData, String> {

    private final com.webauthn4j.converter.CollectedClientDataConverter converter;

    public CollectedClientDataConverter(ObjectConverter objectConverter) {
        this.converter = new com.webauthn4j.converter.CollectedClientDataConverter(objectConverter);
    }

    @Override
    public String convertToDatabaseColumn(CollectedClientData attribute) {
        if (attribute == null) return null;
        return converter.convertToBase64UrlString(attribute);
    }

    @Override
    public CollectedClientData convertToEntityAttribute(String dbData) {
        if (dbData == null) return null;
        return converter.convert(dbData);
    }
}
