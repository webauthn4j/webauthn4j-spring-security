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
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.springframework.security.authenticator.InMemoryWebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.converter.jackson.WebAuthn4JSpringSecurityJSONModule;
import com.webauthn4j.springframework.security.endpoint.AssertionOptionsEndpointFilter;
import com.webauthn4j.springframework.security.endpoint.AttestationOptionsEndpointFilter;
import com.webauthn4j.springframework.security.options.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
public class WebAuthnLoginConfigurerAnotherSpringTest {

    @Autowired
    FilterChainProxy springSecurityFilterChain;

    private MockMvc mvc;

    @Test
    public void rootPath_with_authenticated_user_test() throws Exception {
        mvc = MockMvcBuilders.standaloneSetup()
                .defaultRequest(get("/").with(user("john")))
                .addFilter(springSecurityFilterChain)
                .build();

        mvc
                .perform(get("/"))
                .andExpect(authenticated())
                .andExpect(status().isNotFound());

    }


    @EnableWebSecurity
    static class Config extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.apply(WebAuthnLoginConfigurer.webAuthnLogin());

            // Authorization
            http.authorizeRequests()
                    .antMatchers("/login").permitAll()
                    .anyRequest().authenticated();
        }

        @Configuration
        static class BeanConfig {

            @Bean
            public ObjectConverter objectConverter(){
                ObjectMapper jsonMapper = new ObjectMapper();
                jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
                jsonMapper.registerModule(new WebAuthn4JSpringSecurityJSONModule());
                ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
                return new ObjectConverter(jsonMapper, cborMapper);
            }

            @Bean
            public WebAuthnAuthenticatorService webAuthnAuthenticatorService(){
                return new InMemoryWebAuthnAuthenticatorManager();
            }

            @Bean
            public ChallengeRepository challengeRepository() {
                ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
                when(challengeRepository.loadOrGenerateChallenge(any())).thenReturn(new DefaultChallenge("aFglXMZdQTKD4krvNzJBzA"));
                return challengeRepository;
            }

            @Bean
            public RpIdProvider rpIdProvider(){
                return new RpIdProviderImpl();
            }

            @Bean
            public AttestationOptionsProvider attestationOptionsProvider(RpIdProvider rpIdProvider, WebAuthnAuthenticatorService webAuthnAuthenticatorService, ChallengeRepository challengeRepository){
                return new AttestationOptionsProviderImpl(rpIdProvider, webAuthnAuthenticatorService, challengeRepository);
            }

            @Bean
            public AssertionOptionsProvider assertionOptionsProvider(RpIdProvider rpIdProvider, WebAuthnAuthenticatorService webAuthnAuthenticatorService, ChallengeRepository challengeRepository){
                return new AssertionOptionsProviderImpl(rpIdProvider, webAuthnAuthenticatorService, challengeRepository);
            }

            @Bean
            public AttestationOptionsEndpointFilter attestationOptionsEndpointFilter(AttestationOptionsProvider optionsProvider, ObjectConverter objectConverter){
                return new AttestationOptionsEndpointFilter(optionsProvider, objectConverter);
            }

            @Bean
            public AssertionOptionsEndpointFilter assertionOptionsEndpointFilter(AssertionOptionsProvider optionsProvider, ObjectConverter objectConverter){
                return new AssertionOptionsEndpointFilter(optionsProvider, objectConverter);
            }

        }

    }
}
