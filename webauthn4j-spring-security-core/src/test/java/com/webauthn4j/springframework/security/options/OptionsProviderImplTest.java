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
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import org.assertj.core.util.Lists;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class OptionsProviderImplTest {

    @Test
    public void getAttestationOptions_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[]{0x01, 0x23, 0x45};
        Set<AuthenticatorTransport> transports = Collections.singleton(AuthenticatorTransport.INTERNAL);
        WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);
        WebAuthnAuthenticator authenticator = mock(WebAuthnAuthenticator.class, RETURNS_DEEP_STUBS);
        when(authenticator.getTransports()).thenReturn(transports);
        List<WebAuthnAuthenticator> authenticators = Collections.singletonList(authenticator);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);

        MockHttpServletRequest mockRequest = new MockHttpServletRequest();

        when(authenticatorService.loadAuthenticatorsByUserPrincipal(any())).thenReturn(authenticators);
        when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);
        when(challengeRepository.loadOrGenerateChallenge(mockRequest)).thenReturn(challenge);

        OptionsProviderImpl optionsProvider = new OptionsProviderImpl(authenticatorService, challengeRepository);
        optionsProvider.setRpId("example.com");
        optionsProvider.setRpName("rpName");
        optionsProvider.setRpIcon("data://dummy");
        optionsProvider.setPubKeyCredParams(Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)));
        optionsProvider.setRegistrationTimeout(10000L);
        optionsProvider.setRegistrationExtensions(new AuthenticationExtensionsClientInputs<>());

        PublicKeyCredentialCreationOptions attestationOptions = optionsProvider.getAttestationOptions(mockRequest, new UsernamePasswordAuthenticationToken("username", null));
        assertThat(attestationOptions.getRp().getId()).isEqualTo("example.com");
        assertThat(attestationOptions.getRp().getName()).isEqualTo("rpName");
        assertThat(attestationOptions.getRp().getIcon()).isEqualTo("data://dummy");
        assertThat(attestationOptions.getUser()).isEqualTo(new PublicKeyCredentialUserEntity("username".getBytes(), "username", "username"));
        assertThat(attestationOptions.getChallenge()).isEqualTo(challenge);
        assertThat(attestationOptions.getPubKeyCredParams()).isEqualTo(Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)));
        assertThat(attestationOptions.getTimeout()).isEqualTo(10000L);
        assertThat(attestationOptions.getExcludeCredentials()).containsExactly(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credentialId, transports));
        assertThat(attestationOptions.getExtensions()).isEqualTo(new AuthenticationExtensionsClientInputs<>());

    }

    @Test
    public void getAssertionOptions_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[]{0x01, 0x23, 0x45};
        Set<AuthenticatorTransport> transports = Collections.singleton(AuthenticatorTransport.INTERNAL);
        WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);
        WebAuthnAuthenticator authenticator = mock(WebAuthnAuthenticator.class, RETURNS_DEEP_STUBS);
        when(authenticator.getTransports()).thenReturn(transports);
        List<WebAuthnAuthenticator> authenticators = Collections.singletonList(authenticator);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);

        MockHttpServletRequest mockRequest = new MockHttpServletRequest();

        when(authenticatorService.loadAuthenticatorsByUserPrincipal(any())).thenReturn(authenticators);
        when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);
        when(challengeRepository.loadOrGenerateChallenge(mockRequest)).thenReturn(challenge);

        OptionsProviderImpl optionsProvider = new OptionsProviderImpl(authenticatorService, challengeRepository);
        optionsProvider.setRpId("example.com");
        optionsProvider.setRpName("rpName");
        optionsProvider.setRpIcon("data://dummy");
        optionsProvider.setAuthenticationTimeout(10000L);
        optionsProvider.setAuthenticationUserVerification(UserVerificationRequirement.REQUIRED);
        optionsProvider.setAuthenticationExtensions(new AuthenticationExtensionsClientInputs<>());

        PublicKeyCredentialRequestOptions assertionOptions = optionsProvider.getAssertionOptions(mockRequest, new UsernamePasswordAuthenticationToken("username", null));
        assertThat(assertionOptions.getChallenge()).isEqualTo(challenge);
        assertThat(assertionOptions.getTimeout()).isEqualTo(10000L);
        assertThat(assertionOptions.getRpId()).isEqualTo("example.com");
        assertThat(assertionOptions.getAllowCredentials()).containsExactly(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credentialId, transports));
        assertThat(assertionOptions.getUserVerification()).isEqualTo(UserVerificationRequirement.REQUIRED);
        assertThat(assertionOptions.getExtensions()).isEqualTo(new AuthenticationExtensionsClientInputs<>());

    }

    @Test
    public void getEffectiveRpId() {
        WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
        OptionsProviderImpl optionsProvider = new OptionsProviderImpl(authenticatorService, challengeRepository);
        optionsProvider.setRpId(null);
        MockHttpServletRequest httpServletRequest = new MockHttpServletRequest();
        httpServletRequest.setScheme("https");
        httpServletRequest.setServerName("example.com");
        httpServletRequest.setServerPort(8080);
        assertThat(optionsProvider.getEffectiveRpId(httpServletRequest)).isEqualTo("example.com");

    }

    @Test
    public void getter_setter_test() {
        WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
        OptionsProviderImpl optionsProvider = new OptionsProviderImpl(authenticatorService, challengeRepository);

        optionsProvider.setRpId("example.com");
        assertThat(optionsProvider.getRpId()).isEqualTo("example.com");
        optionsProvider.setRpName("example");
        assertThat(optionsProvider.getRpName()).isEqualTo("example");
        optionsProvider.setRpIcon("data://dummy");
        assertThat(optionsProvider.getRpIcon()).isEqualTo("data://dummy");
        List<PublicKeyCredentialParameters> publicKeyCredParams = Lists.emptyList();
        optionsProvider.setPubKeyCredParams(publicKeyCredParams);
        assertThat(optionsProvider.getPubKeyCredParams()).isEqualTo(publicKeyCredParams);
        optionsProvider.setRegistrationTimeout(10000L);
        assertThat(optionsProvider.getRegistrationTimeout()).isEqualTo(10000L);
        optionsProvider.setAuthenticationTimeout(20000L);
        assertThat(optionsProvider.getAuthenticationTimeout()).isEqualTo(20000L);
        optionsProvider.setRegistrationExtensions(new AuthenticationExtensionsClientInputs<>());
        assertThat(optionsProvider.getRegistrationExtensions()).isEqualTo(new AuthenticationExtensionsClientInputs<>());
        optionsProvider.setAuthenticationExtensions(new AuthenticationExtensionsClientInputs<>());
        assertThat(optionsProvider.getAuthenticationExtensions()).isEqualTo(new AuthenticationExtensionsClientInputs<>());

    }

}
