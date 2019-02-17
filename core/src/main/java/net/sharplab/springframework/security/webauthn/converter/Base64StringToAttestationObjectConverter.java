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

package net.sharplab.springframework.security.webauthn.converter;

import com.fasterxml.jackson.core.ObjectCodec;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.response.attestation.AttestationObject;
import org.springframework.core.convert.converter.Converter;

/**
 * Spring converter which converts from Base64{@link String} to {@link AttestationObject}
 */
public class Base64StringToAttestationObjectConverter implements Converter<String, AttestationObject> {

    //~ Instance fields
    // ================================================================================================
    private AttestationObjectConverter converter;

    // ~ Constructor
    // ========================================================================================================
    public Base64StringToAttestationObjectConverter(CborConverter cborConverter) {
        converter = new AttestationObjectConverter(cborConverter);
    }

    /**
     * Convert Base64 {@link String} to {@link AttestationObject}
     *
     * @param source base64String
     * @return attestationObject
     */
    @Override
    public AttestationObject convert(String source) {
        return converter.convert(source);
    }

}
