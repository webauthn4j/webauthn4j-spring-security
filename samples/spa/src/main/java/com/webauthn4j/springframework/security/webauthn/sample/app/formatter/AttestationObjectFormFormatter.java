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

package com.webauthn4j.springframework.security.webauthn.sample.app.formatter;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.springframework.security.converter.Base64UrlStringToAttestationObjectConverter;
import com.webauthn4j.springframework.security.webauthn.sample.app.api.AttestationObjectForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.Formatter;

import java.text.ParseException;
import java.util.Locale;

/**
 * Converter which converts from {@link AttestationObjectForm} to {@link String}
 */
public class AttestationObjectFormFormatter implements Formatter<AttestationObjectForm> {

    @Autowired
    private Base64UrlStringToAttestationObjectConverter base64UrlStringToAttestationObjectConverter;

    public AttestationObjectFormFormatter(Base64UrlStringToAttestationObjectConverter base64UrlStringToAttestationObjectConverter) {
        this.base64UrlStringToAttestationObjectConverter = base64UrlStringToAttestationObjectConverter;
    }

    @Override
    public AttestationObjectForm parse(String text, Locale locale) throws ParseException {
        AttestationObject attestationObject = base64UrlStringToAttestationObjectConverter.convert(text);
        AttestationObjectForm attestationObjectForm = new AttestationObjectForm();
        attestationObjectForm.setAttestationObject(attestationObject);
        attestationObjectForm.setAttestationObjectBase64(text);
        return attestationObjectForm;
    }

    @Override
    public String print(AttestationObjectForm object, Locale locale) {
        return object.getAttestationObjectBase64();
    }
}
