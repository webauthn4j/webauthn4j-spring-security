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
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.fido.authenticator.WebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.config.configurers.WebAuthnAuthenticationProviderConfigurer;
import com.webauthn4j.springframework.security.config.configurers.WebAuthnConfigurer;
import com.webauthn4j.springframework.security.fido.server.endpoint.FidoServerAssertionOptionsEndpointFilter;
import com.webauthn4j.springframework.security.fido.server.endpoint.FidoServerAssertionResultEndpointFilter;
import com.webauthn4j.springframework.security.fido.server.endpoint.FidoServerAttestationOptionsEndpointFilter;
import com.webauthn4j.springframework.security.fido.server.endpoint.FidoServerAttestationResultEndpointFilter;
import com.webauthn4j.springframework.security.options.OptionsProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.webauthn.sample.app.security.SampleUsernameNotFoundHandler;
import com.webauthn4j.springframework.security.webauthn.sample.domain.component.UserManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.session.SessionManagementFilter;


/**
 * Security Configuration
 */
@Configuration
@Import(value = WebSecurityBeanConfig.class)
@EnableWebSecurity
public class
WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String ADMIN_ROLE = "ADMIN";

    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;

    @Autowired
    private LogoutSuccessHandler logoutSuccessHandler;

    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private DaoAuthenticationProvider daoAuthenticationProvider;

    @Autowired
    private WebAuthnAuthenticatorService authenticatorService;

    @Autowired
    private WebAuthnManager webAuthnManager;

    @Autowired
    private WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator;

    @Autowired
    private UserManager userManager;

    @Autowired
    private ObjectConverter objectConverter;

    @Autowired
    private OptionsProvider optionsProvider;

    @Autowired
    private ServerPropertyProvider serverPropertyProvider;

    @Autowired
    private WebAuthnAuthenticatorManager webAuthnAuthenticatorManager;

    @Autowired
    private ChallengeRepository challengeRepository;

    @Override
    public void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.apply(new WebAuthnAuthenticationProviderConfigurer<>(authenticatorService, webAuthnManager));
    }

    @Override
    public void configure(WebSecurity web) {
        // ignore static resources
        web.ignoring().antMatchers(
                "/favicon.ico",
                "/static/**",
                "/webjars/**",
                "/angular",
                "/angular/**");
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * Configure SecurityFilterChain
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // WebAuthn Config
        http.apply(WebAuthnConfigurer.webAuthn())
                .rpName("WebAuthn4J Spring Security Sample")
                .publicKeyCredParams()
                .addPublicKeyCredParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)  // Windows Hello
                .addPublicKeyCredParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)  // FIDO U2F Key, etc
                .and()
                .registrationExtensions()
                    .entry("example.extension", "test")
                .and()
                .authenticationExtensions()
                    .entry("example.extension", "test")
                .and();


        FidoServerAttestationOptionsEndpointFilter fidoServerAttestationOptionsEndpointFilter = new FidoServerAttestationOptionsEndpointFilter(objectConverter, optionsProvider, challengeRepository);
        FidoServerAttestationResultEndpointFilter fidoServerAttestationResultEndpointFilter = new FidoServerAttestationResultEndpointFilter(objectConverter, userManager, webAuthnAuthenticatorManager, webAuthnRegistrationRequestValidator);
        fidoServerAttestationResultEndpointFilter.setUsernameNotFoundHandler(new SampleUsernameNotFoundHandler(userManager));
        FidoServerAssertionOptionsEndpointFilter fidoServerAssertionOptionsEndpointFilter = new FidoServerAssertionOptionsEndpointFilter(objectConverter, optionsProvider, challengeRepository);
        FidoServerAssertionResultEndpointFilter fidoServerAssertionResultEndpointFilter = new FidoServerAssertionResultEndpointFilter(objectConverter, serverPropertyProvider);
        fidoServerAssertionResultEndpointFilter.setAuthenticationManager(authenticationManagerBean());

        http.addFilterAfter(fidoServerAttestationOptionsEndpointFilter, SessionManagementFilter.class);
        http.addFilterAfter(fidoServerAttestationResultEndpointFilter, SessionManagementFilter.class);
        http.addFilterAfter(fidoServerAssertionOptionsEndpointFilter, SessionManagementFilter.class);
        http.addFilterAfter(fidoServerAssertionResultEndpointFilter, SessionManagementFilter.class);


//        // FIDO Server Endpoints
//        http.apply(fidoServer())
//                .fidoServerAttestationOptionsEndpoint()
//                .and()
//                .fidoServerAttestationResultEndpointConfig()
//                .webAuthnRegistrationRequestValidator(webAuthnRegistrationRequestValidator)
//                .usernameNotFoundHandler(new SampleUsernameNotFoundHandler(userManager))
//                .and()
//                .fidoServerAssertionOptionsEndpointConfig()
//                .and()
//                .fidoServerAssertionResultEndpoint();

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

        http.sessionManagement()
                .sessionAuthenticationFailureHandler(authenticationFailureHandler);

        http.exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler);

        //TODO:
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

        http.csrf().ignoringAntMatchers("/webauthn/**");


    }

}
