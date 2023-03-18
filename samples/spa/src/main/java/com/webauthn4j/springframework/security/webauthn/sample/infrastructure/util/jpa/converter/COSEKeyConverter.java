/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.springframework.security.webauthn.sample.infrastructure.util.jpa.converter;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.COSEKey;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class COSEKeyConverter implements AttributeConverter<COSEKey, byte[]> {

    private final CborConverter cborConverter;

    public COSEKeyConverter(ObjectConverter objectConverter) {
        this.cborConverter = objectConverter.getCborConverter();
    }

    @Override
    public byte[] convertToDatabaseColumn(COSEKey attribute) {
        return cborConverter.writeValueAsBytes(attribute);
    }

    @Override
    public COSEKey convertToEntityAttribute(byte[] dbData) {
        return cborConverter.readValue(dbData, COSEKey.class);
    }
}
