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

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationProvider;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.options.*;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@RunWith(SpringRunner.class)
public class WebAuthnAuthenticationProviderConfigurerSpringTest {

    @Autowired
    ProviderManager providerManager;

    @Test
    public void test() {
        assertThat(providerManager.getProviders()).extracting("class").contains(WebAuthnAuthenticationProvider.class);
    }

    @Configuration
    @EnableWebSecurity
    static class Config {

        @Bean
        public WebAuthnCredentialRecordService webAuthnCredentialRecordService(){
            return mock(WebAuthnCredentialRecordService.class);
        }

        @Bean
        public ChallengeRepository challengeRepository() {
            return new HttpSessionChallengeRepository();
        }

        @Bean
        public AttestationOptionsProvider attestationOptionsProvider(RpIdProvider rpIdProvider, WebAuthnCredentialRecordService webAuthnCredentialRecordService, ChallengeRepository challengeRepository) {
            return new AttestationOptionsProviderImpl(rpIdProvider, webAuthnCredentialRecordService, challengeRepository);
        }

        @Bean
        public AssertionOptionsProvider assertionOptionsProvider(RpIdProvider rpIdProvider, WebAuthnCredentialRecordService webAuthnCredentialRecordService, ChallengeRepository challengeRepository) {
            return new AssertionOptionsProviderImpl(rpIdProvider, webAuthnCredentialRecordService, challengeRepository);
        }

        @Bean
        public RpIdProvider rpIdProvider(){
            return new RpIdProviderImpl();
        }

        @Bean
        public ServerPropertyProvider serverPropertyProvider(RpIdProvider rpIdProvider, ChallengeRepository challengeRepository) {
            return new ServerPropertyProviderImpl(rpIdProvider, challengeRepository);
        }

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            // Authentication
            http.with(WebAuthnLoginConfigurer.webAuthnLogin(), (customizer)->{
            });

            // Authorization
            http.authorizeHttpRequests((authorizeHttpRequestsCustomizer)->{
                authorizeHttpRequestsCustomizer.requestMatchers("/login").permitAll();
                authorizeHttpRequestsCustomizer.anyRequest().authenticated();
            });


            return http.build();
        }

        @Bean
        public AuthenticationManager authenticationManager(WebAuthnCredentialRecordService webAuthnCredentialRecordService) {
            return new ProviderManager(new WebAuthnAuthenticationProvider(webAuthnCredentialRecordService, WebAuthnManager.createNonStrictWebAuthnManager()));
        }

        @Bean(name = "mvcHandlerMappingIntrospector")
        public HandlerMappingIntrospector mvcHandlerMappingIntrospector() {
            return new HandlerMappingIntrospector();
        }
    }
}
