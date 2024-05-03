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

package com.webauthn4j.springframework.security.options;

import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecord;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.exception.PrincipalNotFoundException;
import org.assertj.core.util.Lists;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class AttestationOptionsProviderImplTest {

    @Test
    public void getAttestationOptions_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[]{0x01, 0x23, 0x45};
        Set<AuthenticatorTransport> transports = Collections.singleton(AuthenticatorTransport.INTERNAL);
        RpIdProviderImpl rpIdProvider = new RpIdProviderImpl();
        WebAuthnCredentialRecordService authenticatorService = mock(WebAuthnCredentialRecordService.class);
        WebAuthnCredentialRecord authenticator = mock(WebAuthnCredentialRecord.class, RETURNS_DEEP_STUBS);
        when(authenticator.getTransports()).thenReturn(transports);
        List<WebAuthnCredentialRecord> authenticators = Collections.singletonList(authenticator);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);

        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setServerName("example.com");
        when(authenticatorService.loadCredentialRecordsByUserPrincipal(any())).thenReturn(authenticators);
        when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);
        when(challengeRepository.loadOrGenerateChallenge(mockRequest)).thenReturn(challenge);

        AttestationOptionsProviderImpl optionsProvider = new AttestationOptionsProviderImpl(rpIdProvider, authenticatorService, challengeRepository);
        optionsProvider.setRpName("rpName");
        optionsProvider.setPubKeyCredParams(Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)));
        optionsProvider.setRegistrationTimeout(10000L);
        optionsProvider.setRegistrationExtensions(new AuthenticationExtensionsClientInputs<>());

        AttestationOptions attestationOptions = optionsProvider.getAttestationOptions(mockRequest, new UsernamePasswordAuthenticationToken("username", null));
        assertThat(attestationOptions.getRp().getId()).isEqualTo("example.com");
        assertThat(attestationOptions.getRp().getName()).isEqualTo("rpName");
        assertThat(attestationOptions.getUser()).isEqualTo(new PublicKeyCredentialUserEntity("username".getBytes(), "username", "username"));
        assertThat(attestationOptions.getChallenge()).isEqualTo(challenge);
        assertThat(attestationOptions.getPubKeyCredParams()).isEqualTo(Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)));
        assertThat(attestationOptions.getTimeout()).isEqualTo(10000L);
        assertThat(attestationOptions.getExcludeCredentials()).containsExactly(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credentialId, transports));
        assertThat(attestationOptions.getExtensions()).isEqualTo(new AuthenticationExtensionsClientInputs<>());

    }

    @Test
    public void getAttestationOptions_with_non_existing_principal_test(){
        Challenge challenge = new DefaultChallenge();
        RpIdProviderImpl rpIdProvider = new RpIdProviderImpl();
        WebAuthnCredentialRecordService authenticatorService = mock(WebAuthnCredentialRecordService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);

        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setServerName("example.com");
        when(authenticatorService.loadCredentialRecordsByUserPrincipal(any())).thenThrow(new PrincipalNotFoundException("dummy"));
        when(challengeRepository.loadOrGenerateChallenge(mockRequest)).thenReturn(challenge);

        AttestationOptionsProviderImpl optionsProvider = new AttestationOptionsProviderImpl(rpIdProvider, authenticatorService, challengeRepository);
        optionsProvider.setRpName("rpName");
        optionsProvider.setPubKeyCredParams(Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)));
        optionsProvider.setRegistrationTimeout(10000L);
        optionsProvider.setRegistrationExtensions(new AuthenticationExtensionsClientInputs<>());

        AttestationOptions attestationOptions = optionsProvider.getAttestationOptions(mockRequest, new UsernamePasswordAuthenticationToken("username", null));
        assertThat(attestationOptions.getRp().getId()).isEqualTo("example.com");
        assertThat(attestationOptions.getRp().getName()).isEqualTo("rpName");
        assertThat(attestationOptions.getUser()).isEqualTo(new PublicKeyCredentialUserEntity("username".getBytes(), "username", "username"));
        assertThat(attestationOptions.getChallenge()).isEqualTo(challenge);
        assertThat(attestationOptions.getPubKeyCredParams()).isEqualTo(Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)));
        assertThat(attestationOptions.getTimeout()).isEqualTo(10000L);
        assertThat(attestationOptions.getExcludeCredentials()).isEmpty();
        assertThat(attestationOptions.getExtensions()).isEqualTo(new AuthenticationExtensionsClientInputs<>());
    }

    @Test
    public void getRpId_with_static_rpId(){
        WebAuthnCredentialRecordService authenticatorService = mock(WebAuthnCredentialRecordService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
        AttestationOptionsProviderImpl optionsProvider = new AttestationOptionsProviderImpl(authenticatorService, challengeRepository);
        optionsProvider.setRpId("example.com");

        MockHttpServletRequest request = new MockHttpServletRequest();

        assertThat(optionsProvider.getRpId(request)).isEqualTo("example.com");
    }

    @Test
    public void getRpId_with_rpIdProvider(){
        RpIdProvider rpIdProvider = (HttpServletRequest) -> "example.com";
        WebAuthnCredentialRecordService authenticatorService = mock(WebAuthnCredentialRecordService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
        AttestationOptionsProviderImpl optionsProvider = new AttestationOptionsProviderImpl(rpIdProvider, authenticatorService, challengeRepository);

        MockHttpServletRequest request = new MockHttpServletRequest();

        assertThat(optionsProvider.getRpId(request)).isEqualTo("example.com");
    }

    @Test
    public void getter_setter_test() {
        WebAuthnCredentialRecordService authenticatorService = mock(WebAuthnCredentialRecordService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
        AttestationOptionsProviderImpl optionsProvider = new AttestationOptionsProviderImpl(authenticatorService, challengeRepository);

        optionsProvider.setRpId("example.com");
        assertThat(optionsProvider.getRpId()).isEqualTo("example.com");
        optionsProvider.setRpName("example");
        assertThat(optionsProvider.getRpName()).isEqualTo("example");
        List<PublicKeyCredentialParameters> publicKeyCredParams = Lists.newArrayList();
        optionsProvider.setPubKeyCredParams(publicKeyCredParams);
        assertThat(optionsProvider.getPubKeyCredParams()).isEqualTo(publicKeyCredParams);
        optionsProvider.setRegistrationTimeout(10000L);
        assertThat(optionsProvider.getRegistrationTimeout()).isEqualTo(10000L);
        optionsProvider.setRegistrationExtensions(new AuthenticationExtensionsClientInputs<>());
        assertThat(optionsProvider.getRegistrationExtensions()).isEqualTo(new AuthenticationExtensionsClientInputs<>());


        RpIdProvider rpIdProvider = mock(RpIdProvider.class);
        optionsProvider.setRpIdProvider(rpIdProvider);
        assertThat(optionsProvider.getRpIdProvider()).isEqualTo(rpIdProvider);
        PublicKeyCredentialUserEntityProvider publicKeyCredentialUserEntityProvider = new AttestationOptionsProviderImpl.DefaultPublicKeyCredentialUserEntityProvider();
        optionsProvider.setPublicKeyCredentialUserEntityProvider(publicKeyCredentialUserEntityProvider);
        assertThat(optionsProvider.getPublicKeyCredentialUserEntityProvider()).isEqualTo(publicKeyCredentialUserEntityProvider);

    }

}
