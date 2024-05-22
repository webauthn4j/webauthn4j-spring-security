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
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.FidoMDS3MetadataBLOBProvider;
import com.webauthn4j.metadata.MetadataBLOBProvider;
import com.webauthn4j.metadata.anchor.AggregatingTrustAnchorRepository;
import com.webauthn4j.metadata.anchor.MetadataBLOBBasedTrustAnchorRepository;
import com.webauthn4j.metadata.anchor.MetadataStatementsBasedTrustAnchorRepository;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.credential.InMemoryWebAuthnCredentialRecordManager;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordManager;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.metadata.ResourcesMetadataStatementsProvider;
import com.webauthn4j.springframework.security.options.*;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import com.webauthn4j.springframework.security.webauthn.sample.app.security.ExampleExtensionAuthenticatorOutput;
import com.webauthn4j.springframework.security.webauthn.sample.app.security.ExampleExtensionClientInput;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.validator.attestation.statement.androidkey.AndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.apple.AppleAnonymousAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.TPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessValidator;
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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
public class WebSecurityBeanConfig {

    @Bean
    public WebAuthnCredentialRecordManager webAuthnAuthenticatorManager(){
        return new InMemoryWebAuthnCredentialRecordManager();
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
    public AttestationOptionsProvider attestationOptionsProvider(RpIdProvider rpIdProvider, WebAuthnCredentialRecordService webAuthnCredentialRecordService, ChallengeRepository challengeRepository) {
        return new AttestationOptionsProviderImpl(rpIdProvider, webAuthnCredentialRecordService, challengeRepository);
    }

    @Bean
    public AssertionOptionsProvider assertionOptionsProvider(RpIdProvider rpIdProvider, WebAuthnCredentialRecordService webAuthnCredentialRecordService, ChallengeRepository challengeRepository) {
        return new AssertionOptionsProviderImpl(rpIdProvider, webAuthnCredentialRecordService, challengeRepository);
    }

    @Bean
    public ServerPropertyProvider serverPropertyProvider(ChallengeRepository challengeRepository) {
        return new ServerPropertyProviderImpl(challengeRepository);
    }

    @Bean
    public WebAuthnManager webAuthnManager(
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            ObjectConverter objectConverter
    ) {
        return new WebAuthnManager(
                Arrays.asList(
                        new PackedAttestationStatementValidator(),
                        new FIDOU2FAttestationStatementValidator(),
                        new AndroidKeyAttestationStatementValidator(),
                        new AndroidSafetyNetAttestationStatementValidator(),
                        new TPMAttestationStatementValidator(),
                        new AppleAnonymousAttestationStatementValidator(),
                        new NoneAttestationStatementValidator()
                ),
                certPathTrustworthinessValidator,
                new DefaultSelfAttestationTrustworthinessValidator(),
                objectConverter
        );
    }

    @Bean
    MetadataStatementsBasedTrustAnchorRepository metadataStatementsBasedTrustAnchorRepository(ObjectConverter objectConverter, ResourceLoader resourceLoader){
        ResourcesMetadataStatementsProvider metadataStatementsProvider = new ResourcesMetadataStatementsProvider(objectConverter);
        try {
            Resource[] resources = ResourcePatternUtils.getResourcePatternResolver(resourceLoader).getResources("classpath:metadata/test-tools/*.json");
            metadataStatementsProvider.setResources(Arrays.stream(resources).collect(Collectors.toList()));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return new MetadataStatementsBasedTrustAnchorRepository(metadataStatementsProvider);
    }

    @Bean
    MetadataBLOBBasedTrustAnchorRepository metadataBLOBBasedTrustAnchorRepository(ObjectConverter objectConverter){
        X509Certificate mds3RootCertificate = mds3TestRootCertificate();
        MetadataBLOBProvider[] fidoMDS3MetadataBLOBProviders = Stream.of(
                "https://mds3.fido.tools/execute/b64f714dd9efc2f7011fff6a208e8c170776c326a623788838e43e8c06dd4a4f",
                "https://mds3.fido.tools/execute/c344a84746f6a0978d34cd060e4fab6347f9e86b92cc2adc89e7891a419709c6",
                "https://mds3.fido.tools/execute/1680c9d899447608dd28eeb5779b70c5bdbdb5daef284f90496fc661975d37df",
                "https://mds3.fido.tools/execute/8c7f6fa6e2d058fdef324c2ee435ef4332b968ad8b5a8721717601c100bfb929",
                "https://mds3.fido.tools/execute/a90169bef3866ae087e16b22371721eb9cf1411dab197111807013ef4d8d53ec")
                .map(url -> {
                    try{
                        FidoMDS3MetadataBLOBProvider fidoMDS3MetadataBLOBProvider = new FidoMDS3MetadataBLOBProvider(objectConverter, url, mds3RootCertificate);
                        fidoMDS3MetadataBLOBProvider.setRevocationCheckEnabled(true);
                        fidoMDS3MetadataBLOBProvider.refresh();
                        return fidoMDS3MetadataBLOBProvider;
                    }
                    catch (RuntimeException e){
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .toArray(MetadataBLOBProvider[]::new);

        return new MetadataBLOBBasedTrustAnchorRepository(fidoMDS3MetadataBLOBProviders);
    }

    @Bean
    public DefaultCertPathTrustworthinessValidator defaultCertPathTrustworthinessValidator(
            MetadataStatementsBasedTrustAnchorRepository metadataStatementsBasedTrustAnchorRepository,
            MetadataBLOBBasedTrustAnchorRepository metadataBLOBBasedTrustAnchorRepository) {
        DefaultCertPathTrustworthinessValidator defaultCertPathTrustworthinessValidator = new DefaultCertPathTrustworthinessValidator(new AggregatingTrustAnchorRepository(metadataStatementsBasedTrustAnchorRepository, metadataBLOBBasedTrustAnchorRepository));
        defaultCertPathTrustworthinessValidator.setFullChainProhibited(true);
        return defaultCertPathTrustworthinessValidator;
    }

    public X509Certificate mds3TestRootCertificate(){
        byte[] bytes = Base64Util.decode(
                "MIICaDCCAe6gAwIBAgIPBCqih0DiJLW7+UHXx/o1MAoGCCqGSM49BAMDMGcxCzAJ" +
                        "BgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtF" +
                        "IE1ldGFkYXRhIDMgQkxPQiBST09UIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBG" +
                        "QUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMC" +
                        "VVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRh" +
                        "dGEgMyBCTE9CIFJPT1QgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQ" +
                        "BgcqhkjOPQIBBgUrgQQAIgNiAASKYiz3YltC6+lmxhPKwA1WFZlIqnX8yL5RybSL" +
                        "TKFAPEQeTD9O6mOz+tg8wcSdnVxHzwnXiQKJwhrav70rKc2ierQi/4QUrdsPes8T" +
                        "EirZOkCVJurpDFbXZOgs++pa4XmjYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E" +
                        "BTADAQH/MB0GA1UdDgQWBBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAfBgNVHSMEGDAW" +
                        "gBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAKBggqhkjOPQQDAwNoADBlAjEA/xFsgri0" +
                        "xubSa3y3v5ormpPqCwfqn9s0MLBAtzCIgxQ/zkzPKctkiwoPtDzI51KnAjAmeMyg" +
                        "X2S5Ht8+e+EQnezLJBJXtnkRWY+Zt491wgt/AwSs5PHHMv5QgjELOuMxQBc=");
        return CertificateUtil.generateX509Certificate(bytes);
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
