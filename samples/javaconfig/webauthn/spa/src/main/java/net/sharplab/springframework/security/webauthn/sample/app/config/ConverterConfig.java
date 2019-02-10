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

import com.webauthn4j.registry.Registry;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToAttestationObjectConverter;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToCollectedClientDataConverter;
import net.sharplab.springframework.security.webauthn.sample.app.formatter.AttestationObjectFormFormatter;
import net.sharplab.springframework.security.webauthn.sample.app.formatter.CollectedClientDataFormFormatter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Conversion Service Configuration
 */
@Configuration
public class ConverterConfig {

    private Registry registry = new Registry();

    @Bean
    public Base64StringToCollectedClientDataConverter base64StringToCollectedClientDataConverter(){
        return new Base64StringToCollectedClientDataConverter(registry);
    }

    @Bean
    public Base64StringToAttestationObjectConverter base64StringToWebAuthnAttestationObjectConverter(){
        return new Base64StringToAttestationObjectConverter(registry);
    }

    @Bean
    public CollectedClientDataFormFormatter collectedClientDataFromToBase64StringConverter(
            Base64StringToCollectedClientDataConverter base64StringToCollectedClientDataConverter){
        return new CollectedClientDataFormFormatter(base64StringToCollectedClientDataConverter);
    }

    @Bean
    public AttestationObjectFormFormatter attestationObjectFormFormatter(
            Base64StringToAttestationObjectConverter base64StringToAttestationObjectConverter) {
        return new AttestationObjectFormFormatter(base64StringToAttestationObjectConverter);
    }

}
