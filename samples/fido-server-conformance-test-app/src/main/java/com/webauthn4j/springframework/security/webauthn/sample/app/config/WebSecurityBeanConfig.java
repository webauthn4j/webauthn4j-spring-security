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
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.authenticator.InMemoryWebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.metadata.JsonFileResourceMetadataStatementsProvider;
import com.webauthn4j.springframework.security.metadata.RestTemplateAdaptorHttpClient;
import com.webauthn4j.springframework.security.options.*;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import com.webauthn4j.springframework.security.webauthn.sample.app.security.ExampleExtensionAuthenticatorOutput;
import com.webauthn4j.springframework.security.webauthn.sample.app.security.ExampleExtensionClientInput;
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
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.ResourcePatternUtils;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
public class WebSecurityBeanConfig {

    @Bean
    public WebAuthnAuthenticatorManager webAuthnAuthenticatorManager(){
        return new InMemoryWebAuthnAuthenticatorManager();
    }

    @Bean
    public UserDetailsManager userDetailsManager(){
        return new InMemoryUserDetailsManager();
    }

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
    public RpIdProvider rpIdProvider(){
        return new RpIdProviderImpl();
    }

    @Bean
    public AttestationOptionsProvider attestationOptionsProvider(RpIdProvider rpIdProvider, WebAuthnAuthenticatorService webAuthnAuthenticatorService, ChallengeRepository challengeRepository) {
        return new AttestationOptionsProviderImpl(rpIdProvider, webAuthnAuthenticatorService, challengeRepository);
    }

    @Bean
    public AssertionOptionsProvider assertionOptionsProvider(RpIdProvider rpIdProvider, WebAuthnAuthenticatorService webAuthnAuthenticatorService, ChallengeRepository challengeRepository) {
        return new AssertionOptionsProviderImpl(rpIdProvider, webAuthnAuthenticatorService, challengeRepository);
    }

    @Bean
    public ServerPropertyProvider serverPropertyProvider(ChallengeRepository challengeRepository) {
        return new ServerPropertyProviderImpl(challengeRepository);
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
                new DefaultSelfAttestationTrustworthinessValidator(),
                objectConverter
        );
        webAuthnManager.getRegistrationDataValidator().getCustomRegistrationValidators().add(fidoMdsMetadataValidator);
        return webAuthnManager;
    }

    @Bean
    public FidoMdsMetadataValidator fidoMdsMetadataValidator(MetadataItemsResolver fidoMdsMetadataItemsResolver) {
        return new FidoMdsMetadataValidator(fidoMdsMetadataItemsResolver);
    }

    @Bean
    public CertPathTrustworthinessValidator certPathTrustworthinessValidator(TrustAnchorsResolver trustAnchorsResolver) {
        TrustAnchorCertPathTrustworthinessValidator trustAnchorCertPathTrustworthinessValidator = new TrustAnchorCertPathTrustworthinessValidator(trustAnchorsResolver);
        trustAnchorCertPathTrustworthinessValidator.setFullChainProhibited(true);
        return trustAnchorCertPathTrustworthinessValidator;
    }

    @Bean
    public TrustAnchorsResolver trustAnchorsResolver(TrustAnchorsProvider trustAnchorsProvider) {
        return new TrustAnchorsResolverImpl(trustAnchorsProvider);
    }

    @Bean
    public TrustAnchorsProvider trustAnchorsProvider(MetadataStatementsProvider metadataStatementsProvider) {
        return new MetadataStatementsTrustAnchorsProvider(metadataStatementsProvider);
    }

    @Bean
    public MetadataItemsResolver fidoMdsMetadataItemsResolver(MetadataItemsProvider fidoMetadataItemsProvider) {
        return new MetadataItemsResolverImpl(fidoMetadataItemsProvider);
    }

    @Bean
    public MetadataItemsResolver metadataItemsResolver(MetadataItemsProvider metadataItemsProvider) {
        return new MetadataItemsResolverImpl(metadataItemsProvider);
    }

    @Bean
    public MetadataItemsProvider fidoMetadataItemsProvider(ObjectConverter objectConverter, HttpClient httpClient) {
        X509Certificate conformanceTestCertificate = CertificateUtil.generateX509Certificate(Base64Util.decode("MIICZzCCAe6gAwIBAgIPBF0rd3WL/GExWV/szYNVMAoGCCqGSM49BAMDMGcxCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtFIE1ldGFkYXRhIFRPQyBTaWduaW5nIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBGQUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRhdGEgVE9DIFNpZ25pbmcgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARcVLd6r4fnNHzs5K2zfbg//4X9/oBqmsdRVtZ9iXhlgM9vFYaKviYtqmwkq0D3Lihg3qefeZgXXYi4dFgvzU7ZLBapSNM3CT8RDBe/MBJqsPwaRQbIsGmmItmt/ESNQD6jYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTd95rIHO/hX9Oh69szXzD0ahmZWTAfBgNVHSMEGDAWgBTd95rIHO/hX9Oh69szXzD0ahmZWTAKBggqhkjOPQQDAwNnADBkAjBkP3L99KEXQzviJVGytDMWBmITMBYv1LgNXXiSilWixTyQqHrYrFpLvNFyPZQvS6sCMFMAOUCwAch/515XH0XlDbMgdIe2N4zzdY77TVwiHmsxTFWRT0FtS7fUk85c/LzSPQ=="));
        String[] urls = new String[]{
                "https://fidoalliance.co.nz/mds//execute/0f01c2027d05dc909511d3c18ff14dbe8b109d1df565a3a9c391c1dc08830e13",
                "https://fidoalliance.co.nz/mds//execute/2802bb2f78413bcb303b6b13fdeeaa6d7307d6404659fe01f5fb4dfe0790833d",
                "https://fidoalliance.co.nz/mds//execute/47e932675ec4f0367ca4f439160d89a5973a349a2b14fa36149ea0b308759a48",
                "https://fidoalliance.co.nz/mds//execute/51f1d6448bdfc829ea4b720169a5762339e4015146b52f4d0e21d2c78c890180",
                "https://fidoalliance.co.nz/mds//execute/66b56bf384795298788348b318dad4d678cc2d16552c1ca7c5aefcc7fa1bd700"
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
    public HttpClient fidoMDSClient(RestTemplate restTemplate) {
        return new RestTemplateAdaptorHttpClient(restTemplate);
    }

    @Bean
    public RestTemplate restTemplate() {
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
    public ObjectConverter objectConverter() {
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
        jsonMapper.registerSubtypes(new NamedType(ExampleExtensionClientInput.class, ExampleExtensionClientInput.ID));
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        cborMapper.registerSubtypes(new NamedType(ExampleExtensionAuthenticatorOutput.class, ExampleExtensionAuthenticatorOutput.ID));
        return new ObjectConverter(jsonMapper, cborMapper);
    }

}
