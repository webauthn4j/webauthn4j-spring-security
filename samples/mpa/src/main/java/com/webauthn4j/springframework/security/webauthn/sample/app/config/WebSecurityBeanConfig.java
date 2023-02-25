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

package com.webauthn4j.springframework.security.webauthn.sample.app.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.WebAuthnSecurityExpression;
import com.webauthn4j.springframework.security.authenticator.InMemoryWebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.converter.jackson.WebAuthn4JSpringSecurityJSONModule;
import com.webauthn4j.springframework.security.options.*;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

@Configuration
public class WebSecurityBeanConfig {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsManager userDetailsManager(){
        return new InMemoryUserDetailsManager();
    }

    @Bean
    public WebAuthnAuthenticatorManager webAuthnAuthenticatorManager(){
        return new InMemoryWebAuthnAuthenticatorManager();
    }

    @Bean
    public ObjectConverter objectConverter(){
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
        jsonMapper.registerModule(new WebAuthn4JSpringSecurityJSONModule());
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        return new ObjectConverter(jsonMapper, cborMapper);
    }

    @Bean
    public WebAuthnManager webAuthnManager(ObjectConverter objectConverter){
        return WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }

    @Bean
    public WebAuthnSecurityExpression webAuthnSecurityExpression(){
        return new WebAuthnSecurityExpression();
    }

    @Bean
    public ChallengeRepository challengeRepository() {
        return new HttpSessionChallengeRepository();
    }

    @Bean
    public AttestationOptionsProvider attestationOptionsProvider(RpIdProvider rpIdProvider, WebAuthnAuthenticatorService webAuthnAuthenticatorService, ChallengeRepository challengeRepository){
        return new AttestationOptionsProviderImpl(rpIdProvider, webAuthnAuthenticatorService, challengeRepository);
    }

    @Bean
    public AssertionOptionsProvider assertionOptionsProvider(RpIdProvider rpIdProvider, WebAuthnAuthenticatorService webAuthnAuthenticatorService, ChallengeRepository challengeRepository) {
        return new AssertionOptionsProviderImpl(rpIdProvider, webAuthnAuthenticatorService, challengeRepository);
    }

    @Bean
    public RpIdProvider rpIdProvider(){
        return new RpIdProviderImpl();
    }

    @Bean
    public ServerPropertyProvider serverPropertyProvider(RpIdProvider rpIdProvider, ChallengeRepository challengeRepository){
        return new ServerPropertyProviderImpl(rpIdProvider, challengeRepository);
    }

    @Bean
    public WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator(WebAuthnManager webAuthnManager, ServerPropertyProvider serverPropertyProvider){
        return new WebAuthnRegistrationRequestValidator(webAuthnManager, serverPropertyProvider);
    }

}
