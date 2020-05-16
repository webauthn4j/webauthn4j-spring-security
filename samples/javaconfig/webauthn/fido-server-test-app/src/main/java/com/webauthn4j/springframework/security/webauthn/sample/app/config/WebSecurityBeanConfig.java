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
import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.anchor.TrustAnchorsProvider;
import com.webauthn4j.anchor.TrustAnchorsResolver;
import com.webauthn4j.anchor.TrustAnchorsResolverImpl;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.*;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.webauthn.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.webauthn.metadata.JsonFileResourceMetadataStatementsProvider;
import com.webauthn4j.springframework.security.webauthn.metadata.RestTemplateAdaptorHttpClient;
import com.webauthn4j.springframework.security.webauthn.options.OptionsProvider;
import com.webauthn4j.springframework.security.webauthn.options.OptionsProviderImpl;
import com.webauthn4j.springframework.security.webauthn.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import com.webauthn4j.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.CertificateUtil;
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
import com.webauthn4j.springframework.security.webauthn.sample.app.security.ExampleExtensionAuthenticatorOutput;
import com.webauthn4j.springframework.security.webauthn.sample.app.security.ExampleExtensionClientInput;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.ResourcePatternUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

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
    public ChallengeRepository challengeRepository() {
        return new HttpSessionChallengeRepository();
    }

    @Bean
    public OptionsProvider optionsProvider(WebAuthnUserDetailsService webAuthnUserDetailsService, ChallengeRepository challengeRepository) {
        return new OptionsProviderImpl(webAuthnUserDetailsService, challengeRepository);
    }

    @Bean
    public ServerPropertyProvider serverPropertyProvider(OptionsProvider optionsProvider, ChallengeRepository challengeRepository) {
        return new ServerPropertyProviderImpl(optionsProvider, challengeRepository);
    }

    @Bean
    public WebAuthnManager webAuthnManager(
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            FidoMdsMetadataValidator fidoMdsMetadataValidator,
            ObjectConverter objectConverter
    ) {

        WebAuthnManager webAuthnManager = new WebAuthnManager(
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
                objectConverter
        );
        webAuthnManager.getRegistrationDataValidator().getCustomRegistrationValidators().add(fidoMdsMetadataValidator);
        return webAuthnManager;
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
    public MetadataItemsResolver fidoMdsMetadataItemsResolver(MetadataItemsProvider fidoMetadataItemsProvider){
        return new MetadataItemsResolverImpl(fidoMetadataItemsProvider);
    }

    @Bean
    public MetadataItemsResolver metadataItemsResolver(MetadataItemsProvider metadataItemsProvider){
        return new MetadataItemsResolverImpl(metadataItemsProvider);
    }

    @Bean
    public MetadataItemsProvider fidoMetadataItemsProvider(ObjectConverter objectConverter, HttpClient httpClient){
        X509Certificate conformanceTestCertificate = CertificateUtil.generateX509Certificate(Base64Util.decode("MIICZzCCAe6gAwIBAgIPBF0rd3WL/GExWV/szYNVMAoGCCqGSM49BAMDMGcxCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtFIE1ldGFkYXRhIFRPQyBTaWduaW5nIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBGQUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRhdGEgVE9DIFNpZ25pbmcgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARcVLd6r4fnNHzs5K2zfbg//4X9/oBqmsdRVtZ9iXhlgM9vFYaKviYtqmwkq0D3Lihg3qefeZgXXYi4dFgvzU7ZLBapSNM3CT8RDBe/MBJqsPwaRQbIsGmmItmt/ESNQD6jYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTd95rIHO/hX9Oh69szXzD0ahmZWTAfBgNVHSMEGDAWgBTd95rIHO/hX9Oh69szXzD0ahmZWTAKBggqhkjOPQQDAwNnADBkAjBkP3L99KEXQzviJVGytDMWBmITMBYv1LgNXXiSilWixTyQqHrYrFpLvNFyPZQvS6sCMFMAOUCwAch/515XH0XlDbMgdIe2N4zzdY77TVwiHmsxTFWRT0FtS7fUk85c/LzSPQ=="));
        String[] urls = new String[]{
                "https://fidoalliance.co.nz/mds/execute/24972a67c1d02c6a848f457c5ab1955f63148441e031e4d3d7eaa79e25ae6a46",
                "https://fidoalliance.co.nz/mds/execute/427712e10ca2cb354691740a37cd37496874eb5524709150d7e6f9ebd83917e2",
                "https://fidoalliance.co.nz/mds/execute/6ec77bdf780b80fec995b9083d1bf9659680dfe31b97114b14ae28808b252de2",
                "https://fidoalliance.co.nz/mds/execute/a1715169d003018816bd238b523f03a37b4ce85a8edc299e9afe0e74f27ad6a3",
                "https://fidoalliance.co.nz/mds/execute/b3227b69040df61b7dd2e02285207613c1f1a1f531d5cb10b1c5b85827ed4f96"
        };
        List<MetadataItemsProvider> list = new ArrayList<>();
        Arrays.stream(urls).map(url -> {
            FidoMdsMetadataItemsProvider metadataItemsProvider = new FidoMdsMetadataItemsProvider(objectConverter, httpClient, conformanceTestCertificate);
            metadataItemsProvider.setFidoMetadataServiceEndpoint(url);
            return metadataItemsProvider;
        }).forEach(list::add);
        return new AggregatingMetadataItemsProvider(list);
    }

    @Bean
    public MetadataStatementsProvider metadataStatementsProvider(MetadataItemsProvider metadataItemsProvider, ResourceLoader resourceLoader, ObjectConverter objectConverter) throws IOException {

        List<MetadataStatementsProvider> list = new ArrayList<>();
        list.add(new MetadataItemsMetadataStatementsProvider(metadataItemsProvider));

        JsonFileResourceMetadataStatementsProvider provider = new JsonFileResourceMetadataStatementsProvider(objectConverter);
        Resource[] resources = ResourcePatternUtils.getResourcePatternResolver(resourceLoader).getResources("classpath:metadata/test-tools/*.json");
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
    public ObjectConverter objectConverter(){
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
        jsonMapper.registerSubtypes(new NamedType(ExampleExtensionClientInput.class, ExampleExtensionClientInput.ID));
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        cborMapper.registerSubtypes(new NamedType(ExampleExtensionAuthenticatorOutput.class, ExampleExtensionAuthenticatorOutput.ID));
        return new ObjectConverter(jsonMapper, cborMapper);
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
