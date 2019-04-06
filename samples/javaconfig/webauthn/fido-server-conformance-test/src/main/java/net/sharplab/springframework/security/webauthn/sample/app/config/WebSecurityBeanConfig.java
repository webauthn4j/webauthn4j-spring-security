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

package net.sharplab.springframework.security.webauthn.sample.app.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.anchor.TrustAnchorsProvider;
import com.webauthn4j.anchor.TrustAnchorsResolver;
import com.webauthn4j.anchor.TrustAnchorsResolverImpl;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.metadata.*;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import com.webauthn4j.validator.attestation.statement.androidkey.AndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.TPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.DefaultECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import net.sharplab.springframework.security.webauthn.metadata.JsonFileResourceMetadataStatementsProvider;
import net.sharplab.springframework.security.webauthn.metadata.RestTemplateAdaptorHttpClient;
import net.sharplab.springframework.security.webauthn.options.OptionsProvider;
import net.sharplab.springframework.security.webauthn.options.OptionsProviderImpl;
import net.sharplab.springframework.security.webauthn.sample.app.security.ExampleExtensionAuthenticatorOutput;
import net.sharplab.springframework.security.webauthn.sample.app.security.ExampleExtensionClientInput;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.ResourcePatternUtils;
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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.*;

@Configuration
public class WebSecurityBeanConfig {

    @Bean
    public WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator(WebAuthnRegistrationContextValidator registrationContextValidator, ServerPropertyProvider serverPropertyProvider) {
        WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator = new WebAuthnRegistrationRequestValidator(registrationContextValidator, serverPropertyProvider);
        return webAuthnRegistrationRequestValidator;
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
    public WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator(
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            FidoMdsMetadataValidator fidoMdsMetadataValidator,
            JsonConverter jsonConverter,
            CborConverter cborConverter
    ) {

        WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator = new WebAuthnRegistrationContextValidator(
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
                new DefaultSelfAttestationTrustworthinessValidator(),
                jsonConverter,
                cborConverter
        );
        webAuthnRegistrationContextValidator.getCustomRegistrationValidators().add(fidoMdsMetadataValidator);
        return webAuthnRegistrationContextValidator;
    }

    @Bean
    public FidoMdsMetadataValidator fidoMdsMetadataValidator(MetadataItemsResolver fidoMdsMetadataItemsResolver){
        return new FidoMdsMetadataValidator(fidoMdsMetadataItemsResolver);
    }

    @Bean
    public CertPathTrustworthinessValidator certPathTrustworthinessValidator(TrustAnchorsResolver trustAnchorsResolver){
        TrustAnchorCertPathTrustworthinessValidator trustAnchorCertPathTrustworthinessValidator = new TrustAnchorCertPathTrustworthinessValidator(trustAnchorsResolver);
        trustAnchorCertPathTrustworthinessValidator.setFullChainProhibited(true);
        return trustAnchorCertPathTrustworthinessValidator;
    }

    @Bean
    public TrustAnchorsResolver trustAnchorsResolver(TrustAnchorsProvider trustAnchorsProvider){
        return new TrustAnchorsResolverImpl(trustAnchorsProvider);
    }

    @Bean
    public TrustAnchorsProvider trustAnchorsProvider(MetadataStatementsProvider metadataStatementsProvider){
        return new MetadataStatementsTrustAnchorsProvider(metadataStatementsProvider);
    }

    @Bean
    public WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator(JsonConverter jsonConverter, CborConverter cborConverter) {
        return new WebAuthnAuthenticationContextValidator(jsonConverter, cborConverter);
    }

    @Bean
    public MetadataItemsResolver fidoMdsMetadataItemsResolver(MetadataItemsProvider fidoMetadataItemsProvider){
        return new MetadataItemsResolverImpl(fidoMetadataItemsProvider);
    }

    @Bean
    public MetadataItemsResolver metadataItemsResolver(MetadataItemsProvider metadataItemsProvider){
        return new MetadataItemsResolverImpl(metadataItemsProvider);
    }

    @Bean
    public MetadataItemsProvider fidoMetadataItemsProvider(JsonConverter jsonConverter, HttpClient httpClient){
        X509Certificate conformanceTestCertificate = CertificateUtil.generateX509Certificate(Base64Util.decode("MIICYjCCAeigAwIBAgIPBIdvCXPXJiuD7VW0mgRQMAoGCCqGSM49BAMDMGcxCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtFIE1ldGFkYXRhIFRPQyBTaWduaW5nIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBGQUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRhdGEgVE9DIFNpZ25pbmcgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARcVLd6r4fnNHzs5K2zfbg//4X9/oBqmsdRVtZ9iXhlgM9vFYaKviYtqmwkq0D3Lihg3qefeZgXXYi4dFgvzU7ZLBapSNM3CT8RDBe/MBJqsPwaRQbIsGmmItmt/ESNQD6jWjBYMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MBsGA1UdDgQU3feayBzv4V/ToevbM18w9GoZmVkwGwYDVR0jBBTd95rIHO/hX9Oh69szXzD0ahmZWTAKBggqhkjOPQQDAwNoADBlAjAfT9m8LabIuGS6tXiJmRB91SjJ49dk+sPsn+AKx1/PS3wbHEGnGxDIIcQplYDFcXICMQDi33M/oUlb7RDAmapRBjJxKK+oh7hlSZv4djmZV3YV0JnF1Ed5E4I0f3C04eP0bjw="));
        String[] urls = new String[]{
                "https://fidoalliance.co.nz/mds/execute/45e4b78b2eeae3f0e11cfb3e457d467f15348058970d0e2cec376b4beca0de9a",
                "https://fidoalliance.co.nz/mds/execute/4cfef9dac579c25133b6127100e15888c4a58520d589920c271555da15330423",
                "https://fidoalliance.co.nz/mds/execute/6367772ae0fbe33cea2cc241cccc26ba103bc142711d3e22d1c58b54f2d0d7c7",
                "https://fidoalliance.co.nz/mds/execute/b037f7d0cd90badb983fb36fd22a0258d16023f5bdafa7435ffa7fac6003cb60",
                "https://fidoalliance.co.nz/mds/execute/fd8471ddacd4cf795c8b1ac5099340fd49df25d5b7359b6b8fd084db494664d5"
        };
        List<MetadataItemsProvider> list = new ArrayList<>();
        Arrays.stream(urls).map(url -> {
            FidoMdsMetadataItemsProvider metadataItemsProvider = new FidoMdsMetadataItemsProvider(jsonConverter, httpClient, conformanceTestCertificate);
            metadataItemsProvider.setFidoMetadataServiceEndpoint(url);
            return metadataItemsProvider;
        }).forEach(list::add);
        return new AggregatingMetadataItemsProvider(list);
    }

    @Bean
    public MetadataStatementsProvider metadataStatementsProvider(MetadataItemsProvider metadataItemsProvider, ResourceLoader resourceLoader, JsonConverter jsonConverter) throws IOException {

        List<MetadataStatementsProvider> list = new ArrayList<>();
        list.add(new MetadataItemsMetadataStatementsProvider(metadataItemsProvider));

        JsonFileResourceMetadataStatementsProvider provider = new JsonFileResourceMetadataStatementsProvider(jsonConverter);
        Resource[] resources = ResourcePatternUtils.getResourcePatternResolver(resourceLoader).getResources("classpath:metadataStatements/fido-conformance-tools/*.json");
        provider.setResources(Arrays.asList(resources));
        list.add(provider);

        return new AggregatingMetadataStatementsProvider(list);
    }

    @Bean
    public HttpClient fidoMDSClient(RestTemplate restTemplate){
        return new RestTemplateAdaptorHttpClient(restTemplate);
    }

    @Bean
    public RestTemplate restTemplate(){
        return new RestTemplate();
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
    public JsonConverter jsonConverter() {
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
        jsonMapper.registerSubtypes(new NamedType(ExampleExtensionClientInput.class, ExampleExtensionClientInput.ID));
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        cborMapper.registerSubtypes(new NamedType(ExampleExtensionAuthenticatorOutput.class, ExampleExtensionAuthenticatorOutput.ID));
        return new JsonConverter(jsonMapper, cborMapper);
    }

    @Bean
    public CborConverter cborConverter(JsonConverter jsonConverter){
        return jsonConverter.getCborConverter();
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
