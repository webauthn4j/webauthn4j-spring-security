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

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.WebAuthnSecurityExpression;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.options.OptionsProvider;
import com.webauthn4j.springframework.security.options.OptionsProviderImpl;
import com.webauthn4j.springframework.security.options.PublicKeyCredentialUserEntityService;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import com.webauthn4j.springframework.security.authenticator.InMemoryWebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.webauthn.sample.app.service.SamplePublicKeyCredentialUserEntityService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class WebSecurityBeanConfig {

    @Bean
    public WebAuthnAuthenticatorManager webAuthnAuthenticatorManager(){
        return new InMemoryWebAuthnAuthenticatorManager();
    }

    @Bean
    public WebAuthnManager webAuthnManager(){
        return WebAuthnManager.createNonStrictWebAuthnManager();
    }

    @Bean
    public PublicKeyCredentialUserEntityService publicKeyCredentialUserEntityService(){
        return new SamplePublicKeyCredentialUserEntityService();
    }

    @Bean
    public WebAuthnSecurityExpression webAuthnSecurityExpression(){
        return new WebAuthnSecurityExpression();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public OptionsProvider optionsProvider(WebAuthnAuthenticatorService webAuthnAuthenticatorService, PublicKeyCredentialUserEntityService publicKeyCredentialUserEntityService, ChallengeRepository challengeRepository) {
        return new OptionsProviderImpl(webAuthnAuthenticatorService, publicKeyCredentialUserEntityService, challengeRepository);
    }

    @Bean
    public ChallengeRepository challengeRepository() {
        return new HttpSessionChallengeRepository();
    }

    @Bean
    public ServerPropertyProvider serverPropertyProvider(OptionsProvider optionsProvider, ChallengeRepository challengeRepository){
        return new ServerPropertyProviderImpl(optionsProvider, challengeRepository);
    }

    @Bean
    public WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator(WebAuthnManager webAuthnManager, ServerPropertyProvider serverPropertyProvider){
        return new WebAuthnRegistrationRequestValidator(webAuthnManager, serverPropertyProvider);
    }

}
