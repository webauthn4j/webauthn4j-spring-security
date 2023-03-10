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
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class AssertionOptionsProviderImplTest {

    @Test
    public void getAssertionOptions_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[]{0x01, 0x23, 0x45};
        Set<AuthenticatorTransport> transports = Collections.singleton(AuthenticatorTransport.INTERNAL);
        RpIdProvider rpIdProvider = new RpIdProviderImpl();
        WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);
        WebAuthnAuthenticator authenticator = mock(WebAuthnAuthenticator.class, RETURNS_DEEP_STUBS);
        when(authenticator.getTransports()).thenReturn(transports);
        List<WebAuthnAuthenticator> authenticators = Collections.singletonList(authenticator);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);

        MockHttpServletRequest mockRequest = new MockHttpServletRequest();

        when(authenticatorService.loadAuthenticatorsByUserPrincipal(any())).thenReturn(authenticators);
        when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);
        when(challengeRepository.loadOrGenerateChallenge(mockRequest)).thenReturn(challenge);

        AssertionOptionsProviderImpl assertionOptionsProvider = new AssertionOptionsProviderImpl(rpIdProvider, authenticatorService, challengeRepository);
        assertionOptionsProvider.setRpId("example.com");
        assertionOptionsProvider.setAuthenticationTimeout(10000L);
        assertionOptionsProvider.setAuthenticationUserVerification(UserVerificationRequirement.REQUIRED);
        assertionOptionsProvider.setAuthenticationExtensions(new AuthenticationExtensionsClientInputs<>());

        AssertionOptions assertionOptions = assertionOptionsProvider.getAssertionOptions(mockRequest, new UsernamePasswordAuthenticationToken("username", null));
        assertThat(assertionOptions.getChallenge()).isEqualTo(challenge);
        assertThat(assertionOptions.getTimeout()).isEqualTo(10000L);
        assertThat(assertionOptions.getRpId()).isEqualTo("example.com");
        assertThat(assertionOptions.getAllowCredentials()).containsExactly(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credentialId, transports));
        assertThat(assertionOptions.getUserVerification()).isEqualTo(UserVerificationRequirement.REQUIRED);
        assertThat(assertionOptions.getExtensions()).isEqualTo(new AuthenticationExtensionsClientInputs<>());

    }

    @Test
    public void getRpId_with_static_rpId(){
        WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
        AssertionOptionsProviderImpl optionsProvider = new AssertionOptionsProviderImpl(authenticatorService, challengeRepository);
        optionsProvider.setRpId("example.com");

        MockHttpServletRequest request = new MockHttpServletRequest();

        assertThat(optionsProvider.getRpId()).isEqualTo("example.com");
    }

    @Test
    public void getRpId_with_rpIdProvider(){
        RpIdProvider rpIdProvider = () -> "example.com";
        WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
        AssertionOptionsProviderImpl optionsProvider = new AssertionOptionsProviderImpl(rpIdProvider, authenticatorService, challengeRepository);

        MockHttpServletRequest request = new MockHttpServletRequest();

        assertThat(optionsProvider.getRpId()).isEqualTo("example.com");
    }

    @Test
    public void getter_setter_test() {
        RpIdProvider rpIdProvider = mock(RpIdProvider.class);
        WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
        AssertionOptionsProviderImpl optionsProvider = new AssertionOptionsProviderImpl(null, authenticatorService, challengeRepository);

        optionsProvider.setRpId("example.com");
        assertThat(optionsProvider.getRpId()).isEqualTo("example.com");
        optionsProvider.setRpIdProvider(rpIdProvider);
        assertThat(optionsProvider.getRpIdProvider()).isEqualTo(rpIdProvider);
        optionsProvider.setAuthenticationTimeout(20000L);
        assertThat(optionsProvider.getAuthenticationTimeout()).isEqualTo(20000L);
        optionsProvider.setAuthenticationExtensions(new AuthenticationExtensionsClientInputs<>());
        assertThat(optionsProvider.getAuthenticationExtensions()).isEqualTo(new AuthenticationExtensionsClientInputs<>());

    }

}
