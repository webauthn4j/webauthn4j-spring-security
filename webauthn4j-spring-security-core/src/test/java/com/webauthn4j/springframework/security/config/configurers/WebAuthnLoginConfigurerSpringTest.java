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


import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.springframework.security.WebAuthnProcessingFilter;
import com.webauthn4j.springframework.security.authenticator.InMemoryWebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.options.OptionsProvider;
import com.webauthn4j.springframework.security.options.OptionsProviderImpl;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import org.assertj.core.api.Assertions;
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

import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
public class WebAuthnLoginConfigurerSpringTest {

    @Autowired
    FilterChainProxy springSecurityFilterChain;

    private MockMvc mvc;

    @Autowired
    private ServerPropertyProvider serverPropertyProvider;

    @Test
    public void configured_filter_test() {
        WebAuthnProcessingFilter webAuthnProcessingFilter = (WebAuthnProcessingFilter) springSecurityFilterChain.getFilterChains().get(0).getFilters().stream().filter(item -> item instanceof WebAuthnProcessingFilter).findFirst().orElse(null);
        Assertions.assertThat(webAuthnProcessingFilter.getServerPropertyProvider()).isEqualTo(serverPropertyProvider);
    }


    @Test
    public void rootPath_with_anonymous_user_test() throws Exception {
        mvc = MockMvcBuilders.standaloneSetup()
                .addFilter(springSecurityFilterChain)
                .build();

        mvc
                .perform(get("/").with(anonymous()))
                .andExpect(unauthenticated())
                .andExpect(status().is3xxRedirection());
    }

    @Test
    public void attestationOptionsEndpointPath_with_anonymous_user_test() throws Exception {
        mvc = MockMvcBuilders.standaloneSetup()
                .addFilter(springSecurityFilterChain)
                .build();

        mvc
                .perform(get("/webauthn/attestation/options").with(anonymous()))
                .andExpect(unauthenticated())
                .andExpect(content().json("{\"rp\":{\"id\":\"example.com\",\"name\":\"example\",\"icon\":\"dummy\"},\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7},{\"type\":\"public-key\",\"alg\":-65535}], \"attestation\": \"direct\", \"timeout\":10000,\"excludeCredentials\":[],\"extensions\":{\"credProps\":true, \"uvm\":true, \"unknown\": true, \"extensionProvider\":\"/webauthn/attestation/options\" }}", true))
                .andExpect(status().isOk());
    }

    @Test
    public void assertionOptionsEndpointPath_with_anonymous_user_test() throws Exception {
        mvc = MockMvcBuilders.standaloneSetup()
                .addFilter(springSecurityFilterChain)
                .build();

        mvc
                .perform(get("/webauthn/assertion/options").with(anonymous()))
                .andExpect(unauthenticated())
                .andExpect(content().json("{\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"timeout\":20000,\"rpId\":\"example.com\",\"allowCredentials\":[],\"extensions\":{\"appid\":\"appid\",\"appidExclude\":\"appidExclude\",\"uvm\":true,\"unknown\":true, \"extensionProvider\":\"/webauthn/assertion/options\"}}", true))
                .andExpect(status().isOk());
    }

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

    @Test
    public void attestationOptionsEndpointPath_with_authenticated_user_test() throws Exception {
        mvc = MockMvcBuilders.standaloneSetup()
                .addFilter(springSecurityFilterChain)
                .build();

        mvc
                .perform(get("/webauthn/attestation/options").with(user("john")))
                .andExpect(authenticated())
                .andExpect(content().json("{\"rp\":{\"id\":\"example.com\",\"name\":\"example\",\"icon\":\"dummy\"},\"user\":{\"id\":\"am9obg==\",\"name\":\"john\",\"displayName\":\"john\"},\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7},{\"type\":\"public-key\",\"alg\":-65535}], \"attestation\":\"direct\", \"timeout\":10000,\"excludeCredentials\":[],\"extensions\":{\"credProps\":true, \"uvm\":true, \"unknown\": true, \"extensionProvider\":\"/webauthn/attestation/options\"}}", true))
                .andExpect(status().isOk());
    }

    @Test
    public void assertionOptionsEndpointPath_with_authenticated_user_test() throws Exception {
        mvc = MockMvcBuilders.standaloneSetup()
                .addFilter(springSecurityFilterChain)
                .build();

        mvc
                .perform(get("/webauthn/assertion/options").with(user("john")))
                .andExpect(authenticated())
                .andExpect(content().json("{\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"timeout\":20000,\"rpId\":\"example.com\",\"allowCredentials\":[],\"extensions\":{\"appid\":\"appid\",\"appidExclude\":\"appidExclude\",\"uvm\":true,\"unknown\":true, \"extensionProvider\":\"/webauthn/assertion/options\"}}", true))
                .andExpect(status().isOk());
    }

    @EnableWebSecurity
    static class Config extends WebSecurityConfigurerAdapter {

        @Autowired
        private ObjectConverter objectConverter;

        @Autowired
        private OptionsProvider optionsProvider;

        @Autowired
        private ServerPropertyProvider serverPropertyProvider;

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            // Authentication
            http.apply(WebAuthnConfigurer.webAuthn())
                    .rpId("example.com")
                    .rpIcon("dummy")
                    .rpName("example")
                    .publicKeyCredParams()
                    .addPublicKeyCredParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
                    .addPublicKeyCredParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1)
                    .and()
                    .attestation(AttestationConveyancePreference.DIRECT)
                    .registrationTimeout(10000L)
                    .authenticationTimeout(20000L)
                    .registrationExtensions()
                        .credProps(true)
                        .uvm(true)
                        .entry("unknown", true)
                        .extensionProviders((builder, httpServletRequest) -> {
                            builder.set("extensionProvider", httpServletRequest.getRequestURI());
                        })
                    .and()
                    .authenticationExtensions()
                        .appid("appid")
                        .appidExclude("appidExclude")
                        .uvm(true)
                        .entry("unknown", true)
                        .extensionProviders((builder, httpServletRequest) -> {
                            builder.set("extensionProvider", httpServletRequest.getRequestURI());
                        })
                    .and();

            http.apply(WebAuthnLoginConfigurer.webAuthnLogin())
                    .usernameParameter("username")
                    .passwordParameter("password")
                    .credentialIdParameter("credentialId")
                    .clientDataJSONParameter("clientDataJSON")
                    .authenticatorDataParameter("authenticatorData")
                    .signatureParameter("signature")
                    .clientExtensionsJSONParameter("clientExtensionsJSON")
                    .successForwardUrl("/")
                    .failureForwardUrl("/login")
                    .loginPage("/login")
                    .attestationOptionsEndpoint()
                        .processingUrl("/webauthn/attestation/options")
                        .and()
                    .assertionOptionsEndpoint()
                        .processingUrl("/webauthn/assertion/options")
                        .and()
                    .objectConverter(objectConverter)
                    .optionsProvider(optionsProvider)
                    .serverPropertyProvider(serverPropertyProvider);

            // Authorization
            http.authorizeRequests()
                    .antMatchers("/login").permitAll()
                    .anyRequest().authenticated();
        }

        @Configuration
        static class BeanConfig {

            @Bean
            public ObjectConverter objectConverter() {
                return new ObjectConverter();
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
            public OptionsProvider optionsProvider(WebAuthnAuthenticatorService webAuthnAuthenticatorService, ChallengeRepository challengeRepository) {
                return new OptionsProviderImpl(webAuthnAuthenticatorService, challengeRepository);
            }

            @Bean
            public ServerPropertyProvider serverPropertyProvider(OptionsProvider optionsProvider, ChallengeRepository challengeRepository) {
                return new ServerPropertyProviderImpl(optionsProvider, challengeRepository);
            }

        }

    }
}
