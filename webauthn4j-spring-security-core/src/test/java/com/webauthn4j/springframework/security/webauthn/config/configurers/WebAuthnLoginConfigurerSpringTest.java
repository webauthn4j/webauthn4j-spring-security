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

package com.webauthn4j.springframework.security.webauthn.config.configurers;


import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.CredentialPropertiesExtensionClientInput;
import com.webauthn4j.data.extension.client.FIDOAppIDExtensionClientInput;
import com.webauthn4j.springframework.security.webauthn.WebAuthnProcessingFilter;
import com.webauthn4j.springframework.security.webauthn.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.webauthn.endpoint.OptionsEndpointFilter;
import com.webauthn4j.springframework.security.webauthn.options.OptionsProvider;
import com.webauthn4j.springframework.security.webauthn.options.OptionsProviderImpl;
import com.webauthn4j.springframework.security.webauthn.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import com.webauthn4j.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import com.webauthn4j.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import com.webauthn4j.test.TestDataUtil;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Collection;
import java.util.Collections;

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

    @MockBean
    private WebAuthnUserDetailsService userDetailsService;

    @Autowired
    private ServerPropertyProvider serverPropertyProvider;

    @SuppressWarnings("unchecked")
    @Before
    public void setup() {
        WebAuthnUserDetails mockUserDetails = mock(WebAuthnUserDetails.class);
        Collection authenticators = Collections.singletonList(TestDataUtil.createAuthenticator());
        when(mockUserDetails.getAuthenticators()).thenReturn(authenticators);
        when(mockUserDetails.getUserHandle()).thenReturn(new byte[32]);
        doThrow(new UsernameNotFoundException(null)).when(userDetailsService).loadUserByUsername(null);
        when(userDetailsService.loadUserByUsername(anyString())).thenReturn(mockUserDetails);
    }

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
    public void optionsEndpointPath_with_anonymous_user_test() throws Exception {
        mvc = MockMvcBuilders.standaloneSetup()
                .addFilter(springSecurityFilterChain)
                .build();

        mvc
                .perform(get("/webauthn/options").with(anonymous()))
                .andExpect(unauthenticated())
                .andExpect(content().json("{\"relyingParty\":{\"name\":\"example\",\"icon\":\"dummy\",\"id\":\"example.com\"},\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"pubKeyCredParams\":[{\"type\":\"public-key\", \"alg\": -65535},{\"type\":\"public-key\", \"alg\": -7}],\"registrationTimeout\":10000,\"authenticationTimeout\":20000,\"credentials\":[],\"registrationExtensions\":{},\"authenticationExtensions\":{},\"parameters\":{\"username\":\"username\",\"password\":\"password\",\"credentialId\":\"credentialId\",\"clientDataJSON\":\"clientDataJSON\",\"authenticatorData\":\"authenticatorData\",\"signature\":\"signature\",\"clientExtensionsJSON\":\"clientExtensionsJSON\"}}"))
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
    public void optionsEndpointPath_with_authenticated_user_test() throws Exception {
        mvc = MockMvcBuilders.standaloneSetup()
                .addFilter(springSecurityFilterChain)
                .build();

        mvc
                .perform(get("/webauthn/options").with(user("john")))
                .andExpect(authenticated())
                .andExpect(content().json("{\"relyingParty\":{\"name\":\"example\",\"icon\":\"dummy\",\"id\":\"example.com\"},\"user\":{\"userHandle\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"username\":\"john\"},\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7},{\"type\":\"public-key\",\"alg\":-65535}],\"registrationTimeout\":10000,\"authenticationTimeout\":20000,\"credentials\":[{\"type\":\"public-key\",\"id\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}],\"registrationExtensions\":{},\"authenticationExtensions\":{},\"parameters\":{\"username\":\"username\",\"password\":\"password\",\"credentialId\":\"credentialId\",\"clientDataJSON\":\"clientDataJSON\",\"authenticatorData\":\"authenticatorData\",\"signature\":\"signature\",\"clientExtensionsJSON\":\"clientExtensionsJSON\"}}"))
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
                    .registrationTimeout(10000L)
                    .authenticationTimeout(20000L)
                    .registrationExtensions()
                    .addExtension(new CredentialPropertiesExtensionClientInput(true))
                    .and()
                    .authenticationExtensions()
                    .addExtension(new FIDOAppIDExtensionClientInput(""))
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
                    .optionsEndpoint()
                    .processingUrl("/webauthn/options")
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
            public ChallengeRepository challengeRepository() {
                ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
                when(challengeRepository.loadOrGenerateChallenge(any())).thenReturn(new DefaultChallenge("aFglXMZdQTKD4krvNzJBzA"));
                return challengeRepository;
            }

            @Bean
            public OptionsProvider optionsProvider(WebAuthnUserDetailsService webAuthnUserDetailsService, ChallengeRepository challengeRepository) {
                OptionsProvider optionsProvider = new OptionsProviderImpl(webAuthnUserDetailsService, challengeRepository);
                optionsProvider.setRpId("example.com");
                return optionsProvider;
            }

            @Bean
            public OptionsEndpointFilter optionsEndpointFilter(OptionsProvider optionsProvider, ObjectConverter objectConverter) {
                return new OptionsEndpointFilter(optionsProvider, objectConverter);
            }

            @Bean
            public ServerPropertyProvider serverPropertyProvider(OptionsProvider optionsProvider, ChallengeRepository challengeRepository) {
                return new ServerPropertyProviderImpl(optionsProvider, challengeRepository);
            }

        }

    }
}
