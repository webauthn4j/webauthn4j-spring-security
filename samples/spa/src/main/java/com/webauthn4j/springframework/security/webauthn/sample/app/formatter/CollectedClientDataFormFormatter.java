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

import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.springframework.security.converter.Base64UrlStringToCollectedClientDataConverter;
import com.webauthn4j.springframework.security.webauthn.sample.app.api.CollectedClientDataForm;
import org.springframework.format.Formatter;

import java.text.ParseException;
import java.util.Locale;

/**
 * Converter which converts from {@link CollectedClientDataForm} to {@link String}
 */
public class CollectedClientDataFormFormatter implements Formatter<CollectedClientDataForm> {

    private final Base64UrlStringToCollectedClientDataConverter base64UrlStringToCollectedClientDataConverter;

    public CollectedClientDataFormFormatter(Base64UrlStringToCollectedClientDataConverter base64UrlStringToCollectedClientDataConverter) {
        this.base64UrlStringToCollectedClientDataConverter = base64UrlStringToCollectedClientDataConverter;
    }

    @Override
    public CollectedClientDataForm parse(String text, Locale locale) throws ParseException {
        CollectedClientData collectedClientData = base64UrlStringToCollectedClientDataConverter.convert(text);
        CollectedClientDataForm collectedClientDataForm = new CollectedClientDataForm();
        collectedClientDataForm.setCollectedClientData(collectedClientData);
        collectedClientDataForm.setClientDataBase64(text);
        return collectedClientDataForm;
    }

    @Override
    public String print(CollectedClientDataForm object, Locale locale) {
        return object.getClientDataBase64();
    }
}
