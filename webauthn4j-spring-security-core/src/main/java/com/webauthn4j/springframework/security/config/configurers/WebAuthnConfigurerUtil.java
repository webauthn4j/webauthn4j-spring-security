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

package com.webauthn4j.springframework.security.config.configurers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.converter.jackson.WebAuthn4JSpringSecurityJSONModule;
import com.webauthn4j.springframework.security.endpoint.AssertionOptionsEndpointFilter;
import com.webauthn4j.springframework.security.endpoint.AttestationOptionsEndpointFilter;
import com.webauthn4j.springframework.security.options.OptionsProvider;
import com.webauthn4j.springframework.security.options.OptionsProviderImpl;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

/**
 * Internal utility for WebAuthn Configurers
 */
class WebAuthnConfigurerUtil {

    private WebAuthnConfigurerUtil() {
    }

    static <H extends HttpSecurityBuilder<H>> ChallengeRepository getChallengeRepository(H http) {
        ChallengeRepository challengeRepository = http.getSharedObject(ChallengeRepository.class);
        if (challengeRepository != null) {
            return challengeRepository;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(ChallengeRepository.class);
        if (beanNames.length == 0) {
            return new HttpSessionChallengeRepository();
        } else {
            return applicationContext.getBean(ChallengeRepository.class);
        }
    }

    public static <H extends HttpSecurityBuilder<H>> WebAuthnAuthenticatorService getWebAuthnAuthenticatorService(H http){
        WebAuthnAuthenticatorService webAuthnAuthenticatorService = http.getSharedObject(WebAuthnAuthenticatorService.class);
        if (webAuthnAuthenticatorService != null) {
            return webAuthnAuthenticatorService;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        // WebAuthnAuthenticatorService must be provided manually. If not, let it throw exception.
        return applicationContext.getBean(WebAuthnAuthenticatorService.class);
    }

    public static <H extends HttpSecurityBuilder<H>> OptionsProvider getOptionsProvider(H http) {
        OptionsProvider optionsProvider = http.getSharedObject(OptionsProvider.class);
        if (optionsProvider != null) {
            return optionsProvider;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(OptionsProvider.class);
        if(beanNames.length == 0){
            return new OptionsProviderImpl(getWebAuthnAuthenticatorService(http), getChallengeRepository(http));
        }
        else {
            return applicationContext.getBean(OptionsProvider.class);
        }
    }

    public static <H extends HttpSecurityBuilder<H>> ObjectConverter getObjectConverter(H http) {
        ObjectConverter objectConverter = http.getSharedObject(ObjectConverter.class);
        if (objectConverter != null) {
            return objectConverter;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(ObjectConverter.class);
        if (beanNames.length == 0) {
            ObjectMapper jsonMapper = new ObjectMapper();
            jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
            jsonMapper.registerModule(new WebAuthn4JSpringSecurityJSONModule());
            ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            return new ObjectConverter(jsonMapper, cborMapper);
        } else {
            return applicationContext.getBean(ObjectConverter.class);
        }
    }

    public static <H extends HttpSecurityBuilder<H>> ServerPropertyProvider getServerPropertyProvider(H http) {
        ServerPropertyProvider serverPropertyProvider = http.getSharedObject(ServerPropertyProvider.class);
        if (serverPropertyProvider != null) {
            return serverPropertyProvider;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(ServerPropertyProvider.class);
        if (beanNames.length == 0) {
            return new ServerPropertyProviderImpl(getOptionsProvider(http), getChallengeRepository(http));
        } else {
            return applicationContext.getBean(ServerPropertyProvider.class);
        }
    }

    public static <H extends HttpSecurityBuilder<H>> AttestationOptionsEndpointFilter getAttestationOptionsEndpointFilter(H http) {
        AttestationOptionsEndpointFilter attestationOptionsEndpointFilter = http.getSharedObject(AttestationOptionsEndpointFilter.class);
        if (attestationOptionsEndpointFilter != null) {
            return attestationOptionsEndpointFilter;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(AttestationOptionsEndpointFilter.class);
        if (beanNames.length == 0) {
            return new AttestationOptionsEndpointFilter(getOptionsProvider(http), getObjectConverter(http));
        } else {
            return applicationContext.getBean(AttestationOptionsEndpointFilter.class);
        }
    }

    public static <H extends HttpSecurityBuilder<H>> AssertionOptionsEndpointFilter getAssertionOptionsEndpointFilter(H http) {
        AssertionOptionsEndpointFilter assertionOptionsEndpointFilter = http.getSharedObject(AssertionOptionsEndpointFilter.class);
        if (assertionOptionsEndpointFilter != null) {
            return assertionOptionsEndpointFilter;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(AssertionOptionsEndpointFilter.class);
        if (beanNames.length == 0) {
            return new AssertionOptionsEndpointFilter(getOptionsProvider(http), getObjectConverter(http));
        } else {
            return applicationContext.getBean(AssertionOptionsEndpointFilter.class);
        }
    }


}
