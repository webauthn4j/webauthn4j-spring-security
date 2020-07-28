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
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        ChallengeRepository challengeRepository;
        String[] beanNames = applicationContext.getBeanNamesForType(ChallengeRepository.class);
        if (beanNames.length == 0) {
            challengeRepository = new HttpSessionChallengeRepository();
        } else {
            challengeRepository = applicationContext.getBean(ChallengeRepository.class);
        }
        return challengeRepository;
    }

    public static <H extends HttpSecurityBuilder<H>> OptionsProvider getOptionsProvider(H http) {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        OptionsProvider optionsProvider;
        String[] beanNames = applicationContext.getBeanNamesForType(OptionsProvider.class);
        if (beanNames.length == 0) {
            WebAuthnAuthenticatorService authenticatorService = applicationContext.getBean(WebAuthnAuthenticatorService.class);
            optionsProvider = new OptionsProviderImpl(authenticatorService, getChallengeRepository(http));
        } else {
            optionsProvider = applicationContext.getBean(OptionsProvider.class);
        }
        return optionsProvider;
    }

    public static <H extends HttpSecurityBuilder<H>> ObjectConverter getObjectConverter(H http) {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        ObjectConverter objectConverter;
        String[] beanNames = applicationContext.getBeanNamesForType(ObjectConverter.class);
        if (beanNames.length == 0) {
            ObjectMapper jsonMapper = new ObjectMapper();
            jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
            jsonMapper.registerModule(new WebAuthn4JSpringSecurityJSONModule());
            ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            objectConverter = new ObjectConverter(jsonMapper, cborMapper);
        } else {
            objectConverter = applicationContext.getBean(ObjectConverter.class);
        }
        return objectConverter;
    }

    public static <H extends HttpSecurityBuilder<H>> ServerPropertyProvider getServerPropertyProvider(H http) {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        ServerPropertyProvider serverPropertyProvider;
        String[] beanNames = applicationContext.getBeanNamesForType(ServerPropertyProvider.class);
        if (beanNames.length == 0) {
            serverPropertyProvider = new ServerPropertyProviderImpl(getOptionsProvider(http), getChallengeRepository(http));
        } else {
            serverPropertyProvider = applicationContext.getBean(ServerPropertyProvider.class);
        }
        return serverPropertyProvider;
    }

}
