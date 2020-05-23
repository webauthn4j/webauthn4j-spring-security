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

package com.webauthn4j.springframework.security.webauthn.options;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.springframework.security.webauthn.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import com.webauthn4j.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import com.webauthn4j.util.Base64UrlUtil;
import org.assertj.core.util.Lists;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class OptionsProviderImplTest {

    @Test
    public void getAttestationOptions_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[]{0x01, 0x23, 0x45};
        WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);
        WebAuthnUserDetails userDetails = mock(WebAuthnUserDetails.class);
        Authenticator authenticator = mock(Authenticator.class, RETURNS_DEEP_STUBS);
        List<Authenticator> authenticators = Collections.singletonList(authenticator);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);

        MockHttpServletRequest mockRequest = new MockHttpServletRequest();

        when(userDetailsService.loadUserByUsername(any())).thenReturn(userDetails);
        doReturn(new byte[0]).when(userDetails).getUserHandle();
        doReturn(authenticators).when(userDetails).getAuthenticators();
        when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);
        when(challengeRepository.loadOrGenerateChallenge(mockRequest)).thenReturn(challenge);

        OptionsProvider optionsProvider = new OptionsProviderImpl(userDetailsService, challengeRepository);
        optionsProvider.setRpId("example.com");
        optionsProvider.setRpName("rpName");
        optionsProvider.setRpIcon("data://dummy");

        AttestationOptions attestationOptions = optionsProvider.getAttestationOptions(mockRequest, "dummy", null);
        assertThat(attestationOptions.getRelyingParty().getId()).isEqualTo("example.com");
        assertThat(attestationOptions.getRelyingParty().getName()).isEqualTo("rpName");
        assertThat(attestationOptions.getRelyingParty().getIcon()).isEqualTo("data://dummy");
        assertThat(attestationOptions.getChallenge()).isEqualTo(challenge);
        assertThat(attestationOptions.getCredentials()).containsExactly(Base64UrlUtil.encodeToString(credentialId));

    }

    @Test
    public void getAttestationOptions_with_challenge_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[]{0x01, 0x23, 0x45};
        WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);
        WebAuthnUserDetails userDetails = mock(WebAuthnUserDetails.class);
        Authenticator authenticator = mock(Authenticator.class, RETURNS_DEEP_STUBS);
        List<Authenticator> authenticators = Collections.singletonList(authenticator);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);

        MockHttpServletRequest mockRequest = new MockHttpServletRequest();

        when(userDetailsService.loadUserByUsername(any())).thenReturn(userDetails);
        doReturn(new byte[0]).when(userDetails).getUserHandle();
        doReturn(authenticators).when(userDetails).getAuthenticators();
        when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);

        OptionsProvider optionsProvider = new OptionsProviderImpl(userDetailsService, challengeRepository);
        optionsProvider.setRpId("example.com");
        optionsProvider.setRpName("rpName");
        optionsProvider.setRpIcon("data://dummy");

        AttestationOptions attestationOptions = optionsProvider.getAttestationOptions(mockRequest, "dummy", challenge);
        assertThat(attestationOptions.getRelyingParty().getId()).isEqualTo("example.com");
        assertThat(attestationOptions.getRelyingParty().getName()).isEqualTo("rpName");
        assertThat(attestationOptions.getRelyingParty().getIcon()).isEqualTo("data://dummy");
        assertThat(attestationOptions.getChallenge()).isEqualTo(challenge);
        assertThat(attestationOptions.getCredentials()).containsExactly(Base64UrlUtil.encodeToString(credentialId));

    }

    @Test
    public void getAssertionOptions_with_challenge_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[]{0x01, 0x23, 0x45};
        WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);
        WebAuthnUserDetails userDetails = mock(WebAuthnUserDetails.class);
        Authenticator authenticator = mock(Authenticator.class, RETURNS_DEEP_STUBS);
        List<Authenticator> authenticators = Collections.singletonList(authenticator);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);

        MockHttpServletRequest mockRequest = new MockHttpServletRequest();

        when(userDetailsService.loadUserByUsername(any())).thenReturn(userDetails);
        doReturn(new byte[0]).when(userDetails).getUserHandle();
        doReturn(authenticators).when(userDetails).getAuthenticators();
        when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);

        OptionsProvider optionsProvider = new OptionsProviderImpl(userDetailsService, challengeRepository);
        optionsProvider.setRpId("example.com");
        optionsProvider.setRpName("rpName");

        AssertionOptions attestationOptions = optionsProvider.getAssertionOptions(mockRequest, "dummy", challenge);
        assertThat(attestationOptions.getRpId()).isEqualTo("example.com");
        assertThat(attestationOptions.getChallenge()).isEqualTo(challenge);
        assertThat(attestationOptions.getCredentials()).containsExactly(Base64UrlUtil.encodeToString(credentialId));

    }

    @Test
    public void getEffectiveRpId() {
        WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
        OptionsProviderImpl optionsProvider = new OptionsProviderImpl(userDetailsService, challengeRepository);
        optionsProvider.setRpId(null);
        MockHttpServletRequest httpServletRequest = new MockHttpServletRequest();
        httpServletRequest.setScheme("https");
        httpServletRequest.setServerName("example.com");
        httpServletRequest.setServerPort(8080);
        assertThat(optionsProvider.getEffectiveRpId(httpServletRequest)).isEqualTo("example.com");

    }

    @Test
    public void getter_setter_test() {
        WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
        OptionsProviderImpl optionsProvider = new OptionsProviderImpl(userDetailsService, challengeRepository);

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

        optionsProvider.setUsernameParameter("usernameParameter");
        assertThat(optionsProvider.getUsernameParameter()).isEqualTo("usernameParameter");
        optionsProvider.setPasswordParameter("passwordParameter");
        assertThat(optionsProvider.getPasswordParameter()).isEqualTo("passwordParameter");
        optionsProvider.setCredentialIdParameter("credentialIdParameter");
        assertThat(optionsProvider.getCredentialIdParameter()).isEqualTo("credentialIdParameter");
        optionsProvider.setClientDataJSONParameter("clientDataJSONParameter");
        assertThat(optionsProvider.getClientDataJSONParameter()).isEqualTo("clientDataJSONParameter");
        optionsProvider.setAuthenticatorDataParameter("authenticatorDataParameter");
        assertThat(optionsProvider.getAuthenticatorDataParameter()).isEqualTo("authenticatorDataParameter");
        optionsProvider.setSignatureParameter("signatureParameter");
        assertThat(optionsProvider.getSignatureParameter()).isEqualTo("signatureParameter");
        optionsProvider.setClientExtensionsJSONParameter("clientExtensionsJSONParameter");
        assertThat(optionsProvider.getClientExtensionsJSONParameter()).isEqualTo("clientExtensionsJSONParameter");

    }

}
