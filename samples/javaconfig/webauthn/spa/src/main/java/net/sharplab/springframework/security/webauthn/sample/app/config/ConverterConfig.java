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

package net.sharplab.springframework.security.webauthn.sample.app.config;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import net.sharplab.springframework.security.webauthn.converter.Base64UrlStringToAttestationObjectConverter;
import net.sharplab.springframework.security.webauthn.converter.Base64UrlStringToCollectedClientDataConverter;
import net.sharplab.springframework.security.webauthn.sample.app.formatter.AttestationObjectFormFormatter;
import net.sharplab.springframework.security.webauthn.sample.app.formatter.CollectedClientDataFormFormatter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Conversion Service Configuration
 */
@Configuration
public class ConverterConfig {

    @Bean
    public Base64UrlStringToCollectedClientDataConverter base64StringToCollectedClientDataConverter(JsonConverter jsonConverter){
        return new Base64UrlStringToCollectedClientDataConverter(jsonConverter);
    }

    @Bean
    public Base64UrlStringToAttestationObjectConverter base64StringToWebAuthnAttestationObjectConverter(CborConverter cborConverter){
        return new Base64UrlStringToAttestationObjectConverter(cborConverter);
    }

    @Bean
    public CollectedClientDataFormFormatter collectedClientDataFromToBase64StringConverter(
            Base64UrlStringToCollectedClientDataConverter base64UrlStringToCollectedClientDataConverter){
        return new CollectedClientDataFormFormatter(base64UrlStringToCollectedClientDataConverter);
    }

    @Bean
    public AttestationObjectFormFormatter attestationObjectFormFormatter(
            Base64UrlStringToAttestationObjectConverter base64UrlStringToAttestationObjectConverter) {
        return new AttestationObjectFormFormatter(base64UrlStringToAttestationObjectConverter);
    }

}
