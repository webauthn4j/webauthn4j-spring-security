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

package com.webauthn4j.springframework.security;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecord;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordImpl;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import com.webauthn4j.springframework.security.exception.BadChallengeException;
import com.webauthn4j.springframework.security.exception.CredentialIdNotFoundException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import test.TestUserDetailsImpl;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Test for WebAuthnAuthenticationProvider
 */
public class WebAuthnAuthenticationProviderTest {

    private final WebAuthnCredentialRecordService authenticatorService = mock(WebAuthnCredentialRecordService.class);

    private final WebAuthnManager webAuthnManager = mock(WebAuthnManager.class);

    private WebAuthnAuthenticationProvider authenticationProvider
            = new WebAuthnAuthenticationProvider(authenticatorService, webAuthnManager);

    @Before
    public void setup() {
        authenticationProvider = new WebAuthnAuthenticationProvider(authenticatorService, webAuthnManager);
    }

    /**
     * Verifies that an unsupported authentication token will be rejected.
     */
    @Test(expected = IllegalArgumentException.class)
    public void authenticate_with_invalid_authenticationToken() {
        Authentication token = new UsernamePasswordAuthenticationToken("username", "password");
        authenticationProvider.authenticate(token);
    }

    /**
     * Verifies that the authentication token without credentials will be rejected.
     */
    @Test(expected = BadCredentialsException.class)
    public void authenticate_with_authenticationToken_without_args() {
        Authentication token = new WebAuthnAssertionAuthenticationToken(null, null, null);
        authenticationProvider.authenticate(token);
    }


    /**
     * Verifies that authentication process passes successfully if input is correct.
     */
    @Test
    public void authenticate_test() {
        //Given
        byte[] credentialId = new byte[32];
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        UserDetails webAuthnPrincipal = new TestUserDetailsImpl("dummy", Collections.singletonList(grantedAuthority));
        WebAuthnCredentialRecord webAuthnCredentialRecord = mock(WebAuthnCredentialRecord.class, RETURNS_DEEP_STUBS);
        when(webAuthnCredentialRecord.getUserPrincipal()).thenReturn(webAuthnPrincipal);
        when(webAuthnCredentialRecord.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);

        //When
        WebAuthnAuthenticationRequest request = mock(WebAuthnAuthenticationRequest.class);
        WebAuthnAuthenticationParameters parameters = mock(WebAuthnAuthenticationParameters.class);
        when(request.getCredentialId()).thenReturn(credentialId);
        when(authenticatorService.loadCredentialRecordByCredentialId(credentialId)).thenReturn(webAuthnCredentialRecord);
        when(parameters.getServerProperty()).thenReturn(mock(ServerProperty.class));
        Authentication token = new WebAuthnAssertionAuthenticationToken(request, parameters, null);
        Authentication authenticatedToken = authenticationProvider.authenticate(token);

        ArgumentCaptor<AuthenticationRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationRequest.class);
        ArgumentCaptor<AuthenticationParameters> parameterCaptor = ArgumentCaptor.forClass(AuthenticationParameters.class);
        verify(webAuthnManager).validate(requestCaptor.capture(), parameterCaptor.capture());


        assertThat(authenticatedToken.getPrincipal()).isEqualTo(webAuthnPrincipal);
        assertThat(authenticatedToken.getCredentials()).isEqualTo(request);
        assertThat(authenticatedToken.getAuthorities().toArray()).containsExactly(grantedAuthority);
    }

    /**
     * Verifies that validation fails if ValidationException is thrown from authenticationContextValidator
     */
    @Test(expected = BadChallengeException.class)
    public void authenticate_with_BadChallengeException_from_authenticationContextValidator_test() {
        //Given
        byte[] credentialId = new byte[32];
        WebAuthnCredentialRecordImpl authenticator = mock(WebAuthnCredentialRecordImpl.class, RETURNS_DEEP_STUBS);
        WebAuthnCredentialRecord webAuthnCredentialRecord = mock(WebAuthnCredentialRecord.class);
        when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);
        when(webAuthnCredentialRecord.getAttestedCredentialData()).thenReturn(mock(AttestedCredentialData.class));
        when(webAuthnCredentialRecord.getAttestationStatement()).thenReturn(mock(AttestationStatement.class));

        doThrow(com.webauthn4j.validator.exception.BadChallengeException.class).when(webAuthnManager).validate((AuthenticationRequest) any(), any());

        //When
        WebAuthnAuthenticationRequest request = mock(WebAuthnAuthenticationRequest.class);
        WebAuthnAuthenticationParameters parameters = mock(WebAuthnAuthenticationParameters.class);
        when(request.getCredentialId()).thenReturn(credentialId);
        when(authenticatorService.loadCredentialRecordByCredentialId(credentialId)).thenReturn(webAuthnCredentialRecord);
        when(parameters.getServerProperty()).thenReturn(mock(ServerProperty.class));
        Authentication token = new WebAuthnAssertionAuthenticationToken(request, parameters, null);
        authenticationProvider.authenticate(token);
    }


    @Test
    public void retrieveCredentialRecord_test() {
        byte[] credentialId = new byte[0];
        WebAuthnCredentialRecord expectedAuthenticator = mock(WebAuthnCredentialRecord.class);

        //Given
        when(authenticatorService.loadCredentialRecordByCredentialId(credentialId)).thenReturn(expectedAuthenticator);

        //When
        WebAuthnCredentialRecord webAuthnCredentialRecord = authenticationProvider.retrieveCredentialRecord(credentialId);

        //Then
        assertThat(webAuthnCredentialRecord).isEqualTo(expectedAuthenticator);

    }

    @Test(expected = BadCredentialsException.class)
    public void retrieveWebAuthnUserDetails_test_with_CredentialIdNotFoundException() {
        byte[] credentialId = new byte[0];

        //Given
        when(authenticatorService.loadCredentialRecordByCredentialId(credentialId)).thenThrow(CredentialIdNotFoundException.class);

        //When
        authenticationProvider.retrieveCredentialRecord(credentialId);
    }

    @Test(expected = CredentialIdNotFoundException.class)
    public void retrieveWebAuthnUserDetails_test_with_CredentialIdNotFoundException_and_hideCredentialIdNotFoundExceptions_option_false() {
        byte[] credentialId = new byte[0];

        //Given
        when(authenticatorService.loadCredentialRecordByCredentialId(credentialId)).thenThrow(CredentialIdNotFoundException.class);

        //When
        authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        authenticationProvider.retrieveCredentialRecord(credentialId);
    }

    @Test(expected = InternalAuthenticationServiceException.class)
    public void retrieveWebAuthnUserDetails_test_with_RuntimeException_from_webAuthnAuthenticatorService() {
        byte[] credentialId = new byte[0];

        //Given
        when(authenticatorService.loadCredentialRecordByCredentialId(credentialId)).thenThrow(RuntimeException.class);

        //When
        authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        authenticationProvider.retrieveCredentialRecord(credentialId);
    }

    @Test(expected = InternalAuthenticationServiceException.class)
    public void retrieveWebAuthnUserDetails_test_with_null_from_webAuthnAuthenticatorService() {
        byte[] credentialId = new byte[0];

        //Given
        when(authenticatorService.loadCredentialRecordByCredentialId(credentialId)).thenReturn(null);

        //When
        authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        authenticationProvider.retrieveCredentialRecord(credentialId);
    }

    @Test
    public void getter_setter_test() {
        UserDetailsChecker preAuthenticationChecker = mock(UserDetailsChecker.class);
        UserDetailsChecker postAuthenticationChecker = mock(UserDetailsChecker.class);

        authenticationProvider.setHideCredentialIdNotFoundExceptions(true);
        assertThat(authenticationProvider.isHideCredentialIdNotFoundExceptions()).isTrue();


//        authenticationProvider.setPreAuthenticationChecks(preAuthenticationChecker);
//        assertThat(authenticationProvider.getPreAuthenticationChecks()).isEqualTo(preAuthenticationChecker);
//        authenticationProvider.setPostAuthenticationChecks(postAuthenticationChecker);
//        assertThat(authenticationProvider.getPostAuthenticationChecks()).isEqualTo(postAuthenticationChecker);

    }
//
//    @Test
//    public void userDetailsChecker_check_test() {
//        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
//        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
//        WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
//                new byte[0],
//                "dummy",
//                "dummy",
//                Collections.singletonList(authenticator),
//                Collections.singletonList(grantedAuthority));
//        authenticationProvider.getPreAuthenticationChecks().check(userDetails);
//    }
//
//    @Test(expected = DisabledException.class)
//    public void userDetailsChecker_check_with_disabled_userDetails_test() {
//        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
//        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
//        WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
//                new byte[0],
//                "dummy",
//                "dummy",
//                Collections.singletonList(authenticator),
//                true,
//                false,
//                true,
//                true,
//                true,
//                Collections.singletonList(grantedAuthority));
//        authenticationProvider.getPreAuthenticationChecks().check(userDetails);
//    }
//
//    @Test(expected = AccountExpiredException.class)
//    public void userDetailsChecker_check_with_expired_userDetails_test() {
//        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
//        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
//        WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
//                new byte[0],
//                "dummy",
//                "dummy",
//                Collections.singletonList(authenticator),
//                true,
//                true,
//                false,
//                true,
//                true,
//                Collections.singletonList(grantedAuthority));
//        authenticationProvider.getPreAuthenticationChecks().check(userDetails);
//    }
//
//    @Test(expected = CredentialsExpiredException.class)
//    public void userDetailsChecker_check_with_credentials_expired_userDetails_test() {
//        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
//        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
//        WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
//                new byte[0],
//                "dummy",
//                "dummy",
//                Collections.singletonList(authenticator),
//                true,
//                true,
//                true,
//                false,
//                true,
//                Collections.singletonList(grantedAuthority));
//        authenticationProvider.getPostAuthenticationChecks().check(userDetails);
//    }
//
//    @Test(expected = LockedException.class)
//    public void userDetailsChecker_check_with_locked_userDetails_test() {
//        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
//        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
//        WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
//                new byte[0],
//                "dummy",
//                "dummy",
//                Collections.singletonList(authenticator),
//                true,
//                true,
//                true,
//                true,
//                false,
//                Collections.singletonList(grantedAuthority));
//        authenticationProvider.getPreAuthenticationChecks().check(userDetails);
//    }

}
