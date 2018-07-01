/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.exception.ValidationException;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import net.sharplab.springframework.security.webauthn.exception.*;
import net.sharplab.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsImpl;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test for WebAuthnAuthenticationProvider
 */
public class WebAuthnAuthenticationProviderTest {

    private WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);

    private WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);

    private WebAuthnAuthenticationContextValidator authenticationContextValidator = mock(WebAuthnAuthenticationContextValidator.class);

    private WebAuthnAuthenticationProvider authenticationProvider
            = new WebAuthnAuthenticationProvider(userDetailsService, authenticatorService, authenticationContextValidator);


    /**
     * Verifies that unsupported Authentication object will be rejected.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testInvalidAuthenticationObject() {
        Authentication token = new UsernamePasswordAuthenticationToken("username", "password");
        authenticationProvider.authenticate(token);
    }

    /**
     * Verifies that authentication process passes successfully if input is correct.
     */
    @Test
    public void testAuthenticate() {
        //Given
        byte[] credentialId = new byte[32];
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
        WebAuthnUserDetailsImpl user = new WebAuthnUserDetailsImpl(
                "dummy",
                "dummy",
                Collections.singletonList(authenticator),
                Collections.singletonList(grantedAuthority));

        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId))
                .thenReturn(authenticator);

        //When
        WebAuthnAuthenticationRequest credential = mock(WebAuthnAuthenticationRequest.class);
        when(credential.getCredentialId()).thenReturn(credentialId);
        when(userDetailsService.loadUserByAuthenticator(authenticator)).thenReturn(user);
        Authentication token = new WebAuthnAssertionAuthenticationToken(credential);
        Authentication authenticatedToken = authenticationProvider.authenticate(token);

        assertThat(authenticatedToken.getPrincipal()).isInstanceOf(WebAuthnUserDetailsImpl.class);
        assertThat(authenticatedToken.getCredentials()).isEqualTo(credential);
        assertThat(authenticatedToken.getAuthorities().toArray()).containsExactly(grantedAuthority);
    }

    /**
     * Verifies that authentication process passes successfully if input is correct.
     */
    @Test
    public void testAuthenticate_with_forcePrincipalAsString_option() {
        //Given
        byte[] credentialId = new byte[32];
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
        WebAuthnUserDetailsImpl user = new WebAuthnUserDetailsImpl(
                "dummy",
                "dummy",
                Collections.singletonList(authenticator),
                Collections.singletonList(grantedAuthority));

        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId))
                .thenReturn(authenticator);

        //When
        WebAuthnAuthenticationRequest credential = mock(WebAuthnAuthenticationRequest.class);
        when(credential.getCredentialId()).thenReturn(credentialId);
        when(userDetailsService.loadUserByAuthenticator(authenticator)).thenReturn(user);
        Authentication token = new WebAuthnAssertionAuthenticationToken(credential);
        authenticationProvider.setForcePrincipalAsString(true);
        Authentication authenticatedToken = authenticationProvider.authenticate(token);

        assertThat(authenticatedToken.getPrincipal()).isInstanceOf(String.class);
        assertThat(authenticatedToken.getCredentials()).isEqualTo(credential);
        assertThat(authenticatedToken.getAuthorities().toArray()).containsExactly(grantedAuthority);
    }


    @Test
    public void retrieveWebAuthnAuthenticator_test() {
        byte[] credentialId = new byte[0];
        WebAuthnAssertionAuthenticationToken authenticationToken = null;
        Authenticator expectedAuthenticator = mock(Authenticator.class);

        //Given
        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenReturn(expectedAuthenticator);

        //When
        Authenticator authenticator = authenticationProvider.retrieveWebAuthnAuthenticator(credentialId, authenticationToken);

        //Then
        assertThat(authenticator).isEqualTo(expectedAuthenticator);

    }

    @Test(expected = BadCredentialsException.class)
    public void retrieveWebAuthnAuthenticator_test_with_CredentialIdNotFoundException() {
        byte[] credentialId = new byte[0];
        WebAuthnAssertionAuthenticationToken authenticationToken = null;

        //Given
        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenThrow(CredentialIdNotFoundException.class);

        //When
        authenticationProvider.retrieveWebAuthnAuthenticator(credentialId, authenticationToken);
    }

    @Test(expected = CredentialIdNotFoundException.class)
    public void retrieveWebAuthnAuthenticator_test_with_CredentialIdNotFoundException_and_hideCredentialIdNotFoundExceptions_option_false() {
        byte[] credentialId = new byte[0];
        WebAuthnAssertionAuthenticationToken authenticationToken = null;

        //Given
        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenThrow(CredentialIdNotFoundException.class);

        //When
        authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        authenticationProvider.retrieveWebAuthnAuthenticator(credentialId, authenticationToken);
    }

    @Test(expected = InternalAuthenticationServiceException.class)
    public void retrieveWebAuthnAuthenticator_test_with_RuntimeException_from_webAuthnAuthenticatorService() {
        byte[] credentialId = new byte[0];
        WebAuthnAssertionAuthenticationToken authenticationToken = null;

        //Given
        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenThrow(RuntimeException.class);

        //When
        authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        authenticationProvider.retrieveWebAuthnAuthenticator(credentialId, authenticationToken);
    }

    @Test(expected = InternalAuthenticationServiceException.class)
    public void retrieveWebAuthnAuthenticator_test_with_null_from_webAuthnAuthenticatorService() {
        byte[] credentialId = new byte[0];
        WebAuthnAssertionAuthenticationToken authenticationToken = null;

        //Given
        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenReturn(null);

        //When
        authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        authenticationProvider.retrieveWebAuthnAuthenticator(credentialId, authenticationToken);
    }

    @Test
    public void wrapWithAuthenticationException_test(){

        Map<RuntimeException, Class> map = new HashMap<>();
        map.put(new com.webauthn4j.validator.exception.BadAlgorithmException("dummy"), BadAlgorithmException.class);
        map.put(new com.webauthn4j.validator.exception.BadAttestationStatementException("dummy"), BadAttestationStatementException.class);
        map.put(new com.webauthn4j.validator.exception.BadChallengeException("dummy"), BadChallengeException.class);
        map.put(new com.webauthn4j.validator.exception.BadOriginException("dummy"), BadOriginException.class);
        map.put(new com.webauthn4j.validator.exception.BadRpIdException("dummy"), BadRpIdException.class);
        map.put(new com.webauthn4j.validator.exception.BadSignatureException("dummy"), BadSignatureException.class);
        map.put(new com.webauthn4j.validator.exception.CertificateException("dummy"), CertificateException.class);
        map.put(new com.webauthn4j.validator.exception.ConstraintViolationException("dummy"), ConstraintViolationException.class);
        map.put(new com.webauthn4j.validator.exception.MaliciousCounterValueException("dummy"), MaliciousCounterValueException.class);
        map.put(new com.webauthn4j.validator.exception.MaliciousDataException("dummy"), MaliciousDataException.class);
        map.put(new com.webauthn4j.validator.exception.MissingChallengeException("dummy"), MissingChallengeException.class);
        map.put(new com.webauthn4j.validator.exception.SelfAttestationProhibitedException("dummy"), SelfAttestationProhibitedException.class);
        map.put(new com.webauthn4j.validator.exception.TokenBindingException("dummy"), TokenBindingException.class);
        map.put(new com.webauthn4j.validator.exception.UnexpectedExtensionException("dummy"), UnexpectedExtensionException.class);
        map.put(new com.webauthn4j.validator.exception.UnsupportedAttestationFormatException("dummy"), UnsupportedAttestationFormatException.class);
        map.put(new com.webauthn4j.validator.exception.UserNotPresentException("dummy"), UserNotPresentException.class);
        map.put(new com.webauthn4j.validator.exception.UserNotVerifiedException("dummy"), UserNotVerifiedException.class);
        map.put(new UnknownValidationException("dummy"), AuthenticationServiceException.class);
        map.put(new RuntimeException("dummy"), RuntimeException.class);

        for (Map.Entry<RuntimeException, Class> entry : map.entrySet()){
            assertThat(authenticationProvider.wrapWithAuthenticationException(entry.getKey())).isInstanceOf(entry.getValue());
        }
    }

    @Test
    public void getter_setter_test(){

        authenticationProvider.setForcePrincipalAsString(true);
        assertThat(authenticationProvider.isForcePrincipalAsString()).isTrue();
        authenticationProvider.setHideCredentialIdNotFoundExceptions(true);
        assertThat(authenticationProvider.isHideCredentialIdNotFoundExceptions()).isTrue();
    }


    static class UnknownValidationException extends ValidationException {

        public UnknownValidationException(String message) {
            super(message);
        }
    }
}
