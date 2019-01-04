/*
 *    Copyright 2002-2019 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.sample.app.util.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToAttestationObjectConverter;
import net.sharplab.springframework.security.webauthn.sample.app.api.AttestationObjectForm;
import org.springframework.boot.jackson.JsonComponent;

import java.io.IOException;

/**
 * Jackson Deserializer for {@link AttestationObjectForm}
 */
@JsonComponent
public class AuthenticatorObjectFormDeserializer extends StdDeserializer<AttestationObjectForm> {

    private Base64StringToAttestationObjectConverter base64StringToAttestationObjectConverter;

    public AuthenticatorObjectFormDeserializer(Base64StringToAttestationObjectConverter base64StringToAttestationObjectConverter) {
        super(AttestationObjectForm.class);
        this.base64StringToAttestationObjectConverter = base64StringToAttestationObjectConverter;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AttestationObjectForm deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        String value = p.getValueAsString();
        AttestationObjectForm result = new AttestationObjectForm();
        result.setAttestationObject(base64StringToAttestationObjectConverter.convert(value));
        result.setAttestationObjectBase64(value);
        return result;
    }
}
