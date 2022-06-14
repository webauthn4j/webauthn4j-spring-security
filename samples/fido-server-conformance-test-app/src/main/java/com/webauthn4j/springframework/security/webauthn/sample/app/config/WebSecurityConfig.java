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
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationProvider;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.config.configurers.WebAuthnLoginConfigurer;
import com.webauthn4j.springframework.security.fido.server.endpoint.FidoServerAssertionOptionsEndpointFilter;
import com.webauthn4j.springframework.security.fido.server.endpoint.FidoServerAssertionResultEndpointFilter;
import com.webauthn4j.springframework.security.fido.server.endpoint.FidoServerAttestationOptionsEndpointFilter;
import com.webauthn4j.springframework.security.fido.server.endpoint.FidoServerAttestationResultEndpointFilter;
import com.webauthn4j.springframework.security.options.AssertionOptionsProvider;
import com.webauthn4j.springframework.security.options.AttestationOptionsProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.webauthn.sample.app.security.SampleUsernameNotFoundHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.session.SessionManagementFilter;

import java.util.List;


/**
 * Security Configuration
 */
@Configuration
@Import(value = WebSecurityBeanConfig.class)
@EnableWebSecurity
public class
WebSecurityConfig {

    private static final String ADMIN_ROLE = "ADMIN";

    @Autowired
    private WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator;

    @Autowired
    private UserDetailsManager userDetailsManager;

    @Autowired
    private ObjectConverter objectConverter;

    @Autowired
    private AttestationOptionsProvider attestationOptionsProvider;

    @Autowired
    private AssertionOptionsProvider assertionOptionsProvider;

    @Autowired
    private ServerPropertyProvider serverPropertyProvider;

    @Autowired
    private WebAuthnAuthenticatorManager webAuthnAuthenticatorManager;

    @Autowired
    private ChallengeRepository challengeRepository;

    @Bean
    public WebAuthnAuthenticationProvider webAuthnAuthenticationProvider(WebAuthnAuthenticatorService authenticatorService, WebAuthnManager webAuthnManager){
        return new WebAuthnAuthenticationProvider(authenticatorService, webAuthnManager);
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers){
        return new ProviderManager(providers);
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            // ignore static resources
            web.ignoring().antMatchers(
                    "/favicon.ico",
                    "/static/**",
                    "/webjars/**");
        };
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        // WebAuthn Config
        http.apply(WebAuthnLoginConfigurer.webAuthnLogin())
                .attestationOptionsEndpoint()
                .rp()
                .name("WebAuthn4J Spring Security Sample")
                .and()
                .pubKeyCredParams(
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1),
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.EdDSA)
                )
                .extensions()
                .entry("example.extension", "test")
                .and()
                .assertionOptionsEndpoint()
                .extensions()
                .entry("example.extension", "test")
                .and();

        FidoServerAttestationOptionsEndpointFilter fidoServerAttestationOptionsEndpointFilter = new FidoServerAttestationOptionsEndpointFilter(objectConverter, attestationOptionsProvider, challengeRepository);
        FidoServerAttestationResultEndpointFilter fidoServerAttestationResultEndpointFilter = new FidoServerAttestationResultEndpointFilter(objectConverter, userDetailsManager, webAuthnAuthenticatorManager, webAuthnRegistrationRequestValidator);
        fidoServerAttestationResultEndpointFilter.setUsernameNotFoundHandler(new SampleUsernameNotFoundHandler(userDetailsManager));
        FidoServerAssertionOptionsEndpointFilter fidoServerAssertionOptionsEndpointFilter = new FidoServerAssertionOptionsEndpointFilter(objectConverter, assertionOptionsProvider, challengeRepository);
        FidoServerAssertionResultEndpointFilter fidoServerAssertionResultEndpointFilter = new FidoServerAssertionResultEndpointFilter(objectConverter, serverPropertyProvider);
        fidoServerAssertionResultEndpointFilter.setAuthenticationManager(authenticationManager);

        http.addFilterAfter(fidoServerAttestationOptionsEndpointFilter, SessionManagementFilter.class);
        http.addFilterAfter(fidoServerAttestationResultEndpointFilter, SessionManagementFilter.class);
        http.addFilterAfter(fidoServerAssertionOptionsEndpointFilter, SessionManagementFilter.class);
        http.addFilterAfter(fidoServerAssertionResultEndpointFilter, SessionManagementFilter.class);

        // Authorization
        http.authorizeRequests()
                .mvcMatchers("/").permitAll()
                .mvcMatchers("/api/auth/status").permitAll()
                .mvcMatchers(HttpMethod.GET, "/login").permitAll()
                .mvcMatchers(HttpMethod.POST, "/api/profile").permitAll()
                .mvcMatchers("/health/**").permitAll()
                .mvcMatchers("/info/**").permitAll()
                .mvcMatchers("/h2-console/**").denyAll()
                .mvcMatchers("/api/admin/**").hasRole(ADMIN_ROLE)
                .anyRequest().fullyAuthenticated();

        //TODO:
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

        http.csrf().ignoringAntMatchers("/webauthn/**");

        http.authenticationManager(authenticationManager);

        return http.build();

    }
}
