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
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.converter.jackson.WebAuthn4JSpringSecurityJSONModule;
import com.webauthn4j.springframework.security.options.*;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import com.webauthn4j.springframework.security.webauthn.sample.domain.component.PublicKeyCredentialUserEntityProviderImpl;
import com.webauthn4j.springframework.security.webauthn.sample.domain.component.UserManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.DelegatingAccessDeniedHandler;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.logout.ForwardLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

import java.util.LinkedHashMap;

@Configuration
public class WebSecurityBeanConfig {

    @Bean
    public WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator(WebAuthnManager webAuthnManager, ServerPropertyProvider serverPropertyProvider) {
        return new WebAuthnRegistrationRequestValidator(webAuthnManager, serverPropertyProvider);
    }

    @Bean
    public AuthenticationTrustResolver authenticationTrustResolver() {
        return new AuthenticationTrustResolverImpl();
    }

    @Bean
    public PublicKeyCredentialUserEntityProvider webAuthnUserEntityProvider(UserManager userManager){
        return new PublicKeyCredentialUserEntityProviderImpl(userManager);
    }

    @Bean
    public ChallengeRepository challengeRepository() {
        return new HttpSessionChallengeRepository();
    }

    @Bean
    public AttestationOptionsProvider attestationOptionsProvider(RpIdProvider rpIdProvider, WebAuthnAuthenticatorService webAuthnAuthenticatorService, ChallengeRepository challengeRepository, PublicKeyCredentialUserEntityProvider publicKeyCredentialUserEntityProvider){
        AttestationOptionsProviderImpl optionsProviderImpl = new AttestationOptionsProviderImpl(rpIdProvider, webAuthnAuthenticatorService, challengeRepository);
        optionsProviderImpl.setPublicKeyCredentialUserEntityProvider(publicKeyCredentialUserEntityProvider);
        return optionsProviderImpl;
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
    public ServerPropertyProvider serverPropertyProvider(RpIdProvider rpIdProvider, ChallengeRepository challengeRepository) {
        return new ServerPropertyProviderImpl(rpIdProvider, challengeRepository);
    }

    @Bean
    public WebAuthnManager webAuthnManager(ObjectConverter objectConverter) {

        WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
        webAuthnManager.getAuthenticationDataValidator().setCrossOriginAllowed(true);
        return webAuthnManager;
    }

    @Bean
    public WebAuthnSecurityExpression webAuthnSecurityExpression() {
        return new WebAuthnSecurityExpression();
    }


    @Bean
    public ObjectConverter objectConverter() {
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
        jsonMapper.registerModule(new WebAuthn4JSpringSecurityJSONModule());
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        return new ObjectConverter(jsonMapper, cborMapper);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new ForwardAuthenticationSuccessHandler("/api/status/200");
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        LinkedHashMap<Class<? extends AuthenticationException>, AuthenticationFailureHandler> authenticationFailureHandlers = new LinkedHashMap<>();

        // authenticator error handler
        ForwardAuthenticationFailureHandler authenticationFailureHandler = new ForwardAuthenticationFailureHandler("/api/status/401");
        authenticationFailureHandlers.put(AuthenticationException.class, authenticationFailureHandler);

        // default error handler
        AuthenticationFailureHandler defaultAuthenticationFailureHandler = new ForwardAuthenticationFailureHandler("/api/status/401");

        return new DelegatingAuthenticationFailureHandler(authenticationFailureHandlers, defaultAuthenticationFailureHandler);
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new ForwardLogoutSuccessHandler("/api/status/200");
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        LinkedHashMap<Class<? extends AccessDeniedException>, AccessDeniedHandler> errorHandlers = new LinkedHashMap<>();

        // invalid csrf authenticator error handler
        AccessDeniedHandlerImpl invalidCsrfTokenErrorHandler = new AccessDeniedHandlerImpl();
        invalidCsrfTokenErrorHandler.setErrorPage("/api/status/403");
        errorHandlers.put(InvalidCsrfTokenException.class, invalidCsrfTokenErrorHandler);

        // missing csrf authenticator error handler
        AccessDeniedHandlerImpl missingCsrfTokenErrorHandler = new AccessDeniedHandlerImpl();
        missingCsrfTokenErrorHandler.setErrorPage("/api/status/403");
        errorHandlers.put(MissingCsrfTokenException.class, missingCsrfTokenErrorHandler);

        // default error handler
        AccessDeniedHandlerImpl defaultErrorHandler = new AccessDeniedHandlerImpl();
        defaultErrorHandler.setErrorPage("/api/status/403");

        return new DelegatingAccessDeniedHandler(errorHandlers, defaultErrorHandler);
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        LoginUrlAuthenticationEntryPoint authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint("/api/status/401");
        authenticationEntryPoint.setUseForward(true);
        return authenticationEntryPoint;
    }

}
