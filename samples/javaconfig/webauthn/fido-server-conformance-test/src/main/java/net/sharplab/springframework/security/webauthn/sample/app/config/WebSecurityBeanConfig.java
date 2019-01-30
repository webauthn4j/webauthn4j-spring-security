/*
 *    Copyright 2002-2019 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.sample.app.config;

import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.webauthn4j.anchor.TrustAnchorProvider;
import com.webauthn4j.extras.fido.metadata.FIDOMDSClient;
import com.webauthn4j.extras.fido.metadata.statement.*;
import com.webauthn4j.extras.validator.MetadataStatementCertPathTrustworthinessValidator;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import com.webauthn4j.validator.attestation.statement.androidkey.AndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.TPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.DefaultECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import net.sharplab.springframework.security.webauthn.metadata.FIDOMDSTemplate;
import net.sharplab.springframework.security.webauthn.options.OptionsProvider;
import net.sharplab.springframework.security.webauthn.options.OptionsProviderImpl;
import net.sharplab.springframework.security.webauthn.sample.app.security.ExampleExtensionClientInput;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.MFATokenEvaluator;
import org.springframework.security.authentication.MFATokenEvaluatorImpl;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
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
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.LinkedHashMap;

@Configuration
public class WebSecurityBeanConfig {

    @Bean
    public WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator(WebAuthnRegistrationContextValidator registrationContextValidator, ServerPropertyProvider serverPropertyProvider) {
        return new WebAuthnRegistrationRequestValidator(registrationContextValidator, serverPropertyProvider);
    }

    @Bean
    public AuthenticationTrustResolver authenticationTrustResolver() {
        return new AuthenticationTrustResolverImpl();
    }

    @Bean
    public MFATokenEvaluator mfaTokenEvaluator() {
        return new MFATokenEvaluatorImpl();
    }

    @Bean
    public ChallengeRepository challengeRepository() {
        return new HttpSessionChallengeRepository();
    }

    @Bean
    public OptionsProvider optionsProvider(WebAuthnUserDetailsService webAuthnUserDetailsService, ChallengeRepository challengeRepository) {
        OptionsProvider optionsProvider = new OptionsProviderImpl(webAuthnUserDetailsService, challengeRepository);
        optionsProvider.setRegistrationExtensions(null);
        optionsProvider.setAuthenticationExtensions(null);
        return optionsProvider;
    }

    @Bean
    public ServerPropertyProvider serverPropertyProvider(OptionsProvider optionsProvider, ChallengeRepository challengeRepository) {
        return new ServerPropertyProviderImpl(optionsProvider, challengeRepository);
    }

    @Bean
    public WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator(CertPathTrustworthinessValidator certPathTrustworthinessValidator) {


        return new WebAuthnRegistrationContextValidator(
                Arrays.asList(
                        new PackedAttestationStatementValidator(),
                        new FIDOU2FAttestationStatementValidator(),
                        new AndroidKeyAttestationStatementValidator(),
                        new AndroidSafetyNetAttestationStatementValidator(),
                        new TPMAttestationStatementValidator(),
                        new NoneAttestationStatementValidator()
                ),
                certPathTrustworthinessValidator,
                new DefaultECDAATrustworthinessValidator(),
                new DefaultSelfAttestationTrustworthinessValidator()
        );
    }

    @Bean
    public CertPathTrustworthinessValidator certPathTrustworthinessValidator(MetadataStatementResolver metadataStatementResolver){
        MetadataStatementCertPathTrustworthinessValidator certPathTrustworthinessValidator = new MetadataStatementCertPathTrustworthinessValidator(metadataStatementResolver);
        certPathTrustworthinessValidator.setFullChainProhibited(true);
        return certPathTrustworthinessValidator;
    }

    @Bean
    public WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator(Registry registry) {
        return new WebAuthnAuthenticationContextValidator(registry);
    }

    @Bean
    public MetadataStatementResolver metadataStatementResolver(MetadataStatementProvider metadataStatementProvider){
        return new MetadataStatementResolverImpl(metadataStatementProvider);
    }

    @Bean
    public TrustAnchorProvider trustAnchorProvider(MetadataStatementProvider metadataStatementProvider) {
        return new MetadataStatementTrustAnchorProvider(metadataStatementProvider);
    }

    @Bean
    public MetadataStatementProvider metadataStatementProvider(Registry registry, FIDOMDSClient fidomdsClient) {
        return new FIDOMDSMetadataStatementProvider(registry, fidomdsClient);
    }

    @Bean
    public FIDOMDSClient fidoMDSClient(RestTemplate restTemplate){
        return new FIDOMDSTemplate(restTemplate, "");
    }

    @Bean
    public RestTemplate restTemplate(){
        RestTemplate restTemplate = new RestTemplate();
        return restTemplate;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Not to register DaoAuthenticationProvider to ProviderManager,
    // initialize DaoAuthenticationProvider manually instead of using DaoAuthenticationConfigurer.
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        return daoAuthenticationProvider;
    }

    @Bean
    public Registry registry() {
        Registry registry = new Registry();
        registry.getJsonMapper().registerSubtypes(new NamedType(ExampleExtensionClientInput.class, ExampleExtensionClientInput.ID));
        return registry;
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
