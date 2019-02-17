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

package net.sharplab.springframework.security.webauthn.config.configurers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.util.JsonConverter;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import net.sharplab.springframework.security.webauthn.options.OptionsProvider;
import net.sharplab.springframework.security.webauthn.options.OptionsProviderImpl;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

public class WebAuthnConfigurerUtil {

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
            WebAuthnUserDetailsService userDetailsService = applicationContext.getBean(WebAuthnUserDetailsService.class);
            optionsProvider = new OptionsProviderImpl(userDetailsService, getChallengeRepository(http));
        } else {
            optionsProvider = applicationContext.getBean(OptionsProvider.class);
        }
        return optionsProvider;
    }

    public static <H extends HttpSecurityBuilder<H>> JsonConverter getJsonConverter(H http) {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        JsonConverter jsonConverter;
        String[] beanNames = applicationContext.getBeanNamesForType(JsonConverter.class);
        if (beanNames.length == 0) {
            jsonConverter = new JsonConverter();
        } else {
            jsonConverter = applicationContext.getBean(JsonConverter.class);
        }
        return jsonConverter;
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

    public static <H extends HttpSecurityBuilder<H>> WebAuthnUserDetailsService getWebAuthnUserDetailsService(H http) {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        return applicationContext.getBean(WebAuthnUserDetailsService.class);
    }

    public static <H extends HttpSecurityBuilder<H>> WebAuthnRegistrationRequestValidator getWebAuthnRegistrationRequestValidator(H http) {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        return applicationContext.getBean(WebAuthnRegistrationRequestValidator.class);
    }
}
