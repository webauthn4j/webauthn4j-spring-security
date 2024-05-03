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
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.springframework.security.DefaultUserVerificationStrategy;
import com.webauthn4j.springframework.security.UserVerificationStrategy;
import com.webauthn4j.springframework.security.WebAuthnProcessingFilter;
import com.webauthn4j.springframework.security.credential.InMemoryWebAuthnCredentialRecordManager;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.options.AssertionOptionsProvider;
import com.webauthn4j.springframework.security.options.AssertionOptionsProviderImpl;
import com.webauthn4j.springframework.security.options.AttestationOptionsProvider;
import com.webauthn4j.springframework.security.options.AttestationOptionsProviderImpl;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

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
                .andExpect(content().json("{\"rp\":{\"id\":\"example.com\",\"name\":\"example\"},\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7},{\"type\":\"public-key\",\"alg\":-65535}],\"timeout\":10000,\"excludeCredentials\":[],\"authenticatorSelection\":{\"authenticatorAttachment\":\"cross-platform\",\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"},\"attestation\":\"direct\",\"extensions\":{\"uvm\":true,\"credProps\":true,\"extensionProvider\":\"/webauthn/attestation/options\",\"unknown\":true}}", true))
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
                .andExpect(content().json("{\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"timeout\":20000,\"rpId\":\"example.com\",\"allowCredentials\":[],\"userVerification\":\"preferred\",\"extensions\":{\"appid\":\"appid\",\"appidExclude\":\"appidExclude\",\"uvm\":true,\"extensionProvider\":\"/webauthn/assertion/options\",\"unknown\":true}}", true))
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
                .andExpect(content().json("{\"rp\":{\"id\":\"example.com\",\"name\":\"example\"},\"user\":{\"id\":\"am9obg==\",\"name\":\"john\",\"displayName\":\"john\"},\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7},{\"type\":\"public-key\",\"alg\":-65535}],\"timeout\":10000,\"excludeCredentials\":[],\"authenticatorSelection\":{\"authenticatorAttachment\":\"cross-platform\",\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"},\"attestation\":\"direct\",\"extensions\":{\"uvm\":true,\"credProps\":true,\"extensionProvider\":\"/webauthn/attestation/options\",\"unknown\":true}}", true))
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
                .andDo(item ->
                        item.getResponse().getContentAsString()
                )
                .andExpect(content().json("{\"challenge\":\"aFglXMZdQTKD4krvNzJBzA\",\"timeout\":20000,\"rpId\":\"example.com\",\"allowCredentials\":[],\"userVerification\":\"preferred\",\"extensions\":{\"appid\":\"appid\",\"appidExclude\":\"appidExclude\",\"uvm\":true,\"extensionProvider\":\"/webauthn/assertion/options\",\"unknown\":true}}", true))
                .andExpect(status().isOk());
    }

    @Configuration
    @EnableWebSecurity
    static class Config {

        @Autowired
        private ObjectConverter objectConverter;

        @Autowired
        private AssertionOptionsProvider optionsProvider;

        @Autowired
        private ServerPropertyProvider serverPropertyProvider;

        @Autowired
        private AuthenticationTrustResolver trustResolver;

        @Autowired
        private UserVerificationStrategy userVerificationStrategy;

        @Autowired
        private AttestationOptionsProvider attestationOptionsProvider;
        @Autowired
        private AssertionOptionsProvider assertionOptionsProvider;

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http.with(WebAuthnLoginConfigurer.webAuthnLogin(), (customizer)->{
                customizer.objectConverter(objectConverter)
                        .serverPropertyProvider(serverPropertyProvider)
                        .trustResolver(trustResolver)
                        .userVerificationStrategy(userVerificationStrategy)
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .credentialIdParameter("credentialId")
                        .clientDataJSONParameter("clientDataJSON")
                        .authenticatorDataParameter("authenticatorData")
                        .signatureParameter("signature")
                        .clientExtensionsJSONParameter("clientExtensionsJSON")
                        .loginProcessingUrl("/login")
                        .successForwardUrl("/")
                        .failureForwardUrl("/login")
                        .loginPage("/login")
                        .rpId("example.com")
                        .attestationOptionsEndpoint()
                        .attestationOptionsProvider(attestationOptionsProvider)
                        .processingUrl("/webauthn/attestation/options")
                        .rp()
                        .id("example.com")
                        .name("example")
                        .and()
                        .pubKeyCredParams(
                                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1)
                        )
                        .timeout(10000L)
                        .authenticatorSelection()
                        .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
                        .residentKey(ResidentKeyRequirement.PREFERRED)
                        .userVerification(UserVerificationRequirement.PREFERRED)
                        .and()
                        .attestation(AttestationConveyancePreference.DIRECT)
                        .extensions()
                        .credProps(true)
                        .uvm(true)
                        .entry("unknown", true)
                        .extensionProviders((builder, httpServletRequest) -> builder.set("extensionProvider", httpServletRequest.getRequestURI()))
                        .and()
                        .assertionOptionsEndpoint()
                        .assertionOptionsProvider(assertionOptionsProvider)
                        .processingUrl("/webauthn/assertion/options")
                        .rpId("example.com")
                        .timeout(20000L)
                        .userVerification(UserVerificationRequirement.PREFERRED)
                        .extensions()
                        .appid("appid")
                        .appidExclude("appidExclude")
                        .uvm(true)
                        .entry("unknown", true)
                        .extensionProviders((builder, httpServletRequest) -> {
                            builder.set("extensionProvider", httpServletRequest.getRequestURI());
                        })
                        .and()
                        .and();
            });

            // Authorization
            http.authorizeHttpRequests(authorizeHttpRequestsCustomizer->{
                authorizeHttpRequestsCustomizer.requestMatchers("/login").permitAll();
                authorizeHttpRequestsCustomizer.anyRequest().authenticated();
            });

            return http.build();
        }

        @Configuration
        static class BeanConfig {

            @Bean
            public ObjectConverter objectConverter() {
                return new ObjectConverter();
            }

            @Bean
            public WebAuthnCredentialRecordService webAuthnAuthenticatorService(){
                return new InMemoryWebAuthnCredentialRecordManager();
            }

            @Bean
            public ChallengeRepository challengeRepository() {
                ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
                when(challengeRepository.loadOrGenerateChallenge(any())).thenReturn(new DefaultChallenge("aFglXMZdQTKD4krvNzJBzA"));
                return challengeRepository;
            }

            @Bean
            public AttestationOptionsProvider attestationOptionsProvider(WebAuthnCredentialRecordService webAuthnCredentialRecordService, ChallengeRepository challengeRepository){
                return new AttestationOptionsProviderImpl(webAuthnCredentialRecordService, challengeRepository);
            }

            @Bean
            public AssertionOptionsProviderImpl assertionOptionsProvider(WebAuthnCredentialRecordService webAuthnCredentialRecordService, ChallengeRepository challengeRepository) {
                return new AssertionOptionsProviderImpl(webAuthnCredentialRecordService, challengeRepository);
            }

            @Bean
            public ServerPropertyProvider serverPropertyProvider(ChallengeRepository challengeRepository) {
                return new ServerPropertyProviderImpl(challengeRepository);
            }

            @Bean
            public UserVerificationStrategy userVerificationStrategy(AuthenticationTrustResolver authenticationTrustResolver){
                return new DefaultUserVerificationStrategy(authenticationTrustResolver);
            }

            @Bean
            public AuthenticationTrustResolver authenticationTrustResolver(){
                return new AuthenticationTrustResolverImpl();
            }

            @Bean(name = "mvcHandlerMappingIntrospector")
            public HandlerMappingIntrospector mvcHandlerMappingIntrospector() {
                return new HandlerMappingIntrospector();
            }

        }

    }
}
