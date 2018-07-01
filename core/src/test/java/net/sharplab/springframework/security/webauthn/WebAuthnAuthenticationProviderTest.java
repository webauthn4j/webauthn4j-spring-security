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

import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.exception.ValidationException;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import net.sharplab.springframework.security.webauthn.exception.*;
import net.sharplab.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsImpl;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsChecker;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Test for WebAuthnAuthenticationProvider
 */
public class WebAuthnAuthenticationProviderTest {

    private WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);

    private WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);

    private WebAuthnAuthenticationContextValidator authenticationContextValidator = mock(WebAuthnAuthenticationContextValidator.class);

    private WebAuthnAuthenticationProvider authenticationProvider
            = new WebAuthnAuthenticationProvider(userDetailsService, authenticatorService, authenticationContextValidator);

    @Before
    public void setup(){
        authenticationProvider = new WebAuthnAuthenticationProvider(userDetailsService, authenticatorService, authenticationContextValidator);
        authenticationProvider.setExpectedAuthenticationExtensionIds(Collections.singletonList("appId"));
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
    public void authenticate_with_authenticationToken_without_credentials() {
        Authentication token = new WebAuthnAssertionAuthenticationToken(null);
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

        ArgumentCaptor<WebAuthnAuthenticationContext> captor = ArgumentCaptor.forClass(WebAuthnAuthenticationContext.class);
        verify(authenticationContextValidator).validate(captor.capture(), any());
        WebAuthnAuthenticationContext authenticationContext = captor.getValue();

        assertThat(authenticationContext.getExpectedExtensionIds()).isEqualTo(authenticationProvider.getExpectedAuthenticationExtensionIds());

        assertThat(authenticatedToken.getPrincipal()).isInstanceOf(WebAuthnUserDetailsImpl.class);
        assertThat(authenticatedToken.getCredentials()).isEqualTo(credential);
        assertThat(authenticatedToken.getAuthorities().toArray()).containsExactly(grantedAuthority);
    }

    /**
     * Verifies that authentication process passes successfully if input is correct.
     */
    @Test
    public void authenticate_with_forcePrincipalAsString_option_test() {
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

    /**
     * Verifies that validation fails if ValidationException is thrown from authenticationContextValidator
     */
    @Test(expected = BadChallengeException.class)
    public void authenticate_with_BadChallengeException_from_authenticationContextValidator_test() {
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

        doThrow(com.webauthn4j.validator.exception.BadChallengeException.class).when(authenticationContextValidator).validate(any(), any());

        //When
        WebAuthnAuthenticationRequest credential = mock(WebAuthnAuthenticationRequest.class);
        when(credential.getCredentialId()).thenReturn(credentialId);
        when(userDetailsService.loadUserByAuthenticator(authenticator)).thenReturn(user);
        Authentication token = new WebAuthnAssertionAuthenticationToken(credential);
        authenticationProvider.authenticate(token);
    }



    @Test
    public void retrieveWebAuthnAuthenticator_test() {
        byte[] credentialId = new byte[0];
        Authenticator expectedAuthenticator = mock(Authenticator.class);

        //Given
        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenReturn(expectedAuthenticator);

        //When
        Authenticator authenticator = authenticationProvider.retrieveWebAuthnAuthenticator(credentialId);

        //Then
        assertThat(authenticator).isEqualTo(expectedAuthenticator);

    }

    @Test(expected = BadCredentialsException.class)
    public void retrieveWebAuthnAuthenticator_test_with_CredentialIdNotFoundException() {
        byte[] credentialId = new byte[0];

        //Given
        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenThrow(CredentialIdNotFoundException.class);

        //When
        authenticationProvider.retrieveWebAuthnAuthenticator(credentialId);
    }

    @Test(expected = CredentialIdNotFoundException.class)
    public void retrieveWebAuthnAuthenticator_test_with_CredentialIdNotFoundException_and_hideCredentialIdNotFoundExceptions_option_false() {
        byte[] credentialId = new byte[0];

        //Given
        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenThrow(CredentialIdNotFoundException.class);

        //When
        authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        authenticationProvider.retrieveWebAuthnAuthenticator(credentialId);
    }

    @Test(expected = InternalAuthenticationServiceException.class)
    public void retrieveWebAuthnAuthenticator_test_with_RuntimeException_from_webAuthnAuthenticatorService() {
        byte[] credentialId = new byte[0];

        //Given
        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenThrow(RuntimeException.class);

        //When
        authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        authenticationProvider.retrieveWebAuthnAuthenticator(credentialId);
    }

    @Test(expected = InternalAuthenticationServiceException.class)
    public void retrieveWebAuthnAuthenticator_test_with_null_from_webAuthnAuthenticatorService() {
        byte[] credentialId = new byte[0];

        //Given
        when(authenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId)).thenReturn(null);

        //When
        authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
        authenticationProvider.retrieveWebAuthnAuthenticator(credentialId);
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
        WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);
        WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);
        UserDetailsChecker preAuthenticationChecker = mock(UserDetailsChecker.class);
        UserDetailsChecker postAuthenticationChecker = mock(UserDetailsChecker.class);

        authenticationProvider.setForcePrincipalAsString(true);
        assertThat(authenticationProvider.isForcePrincipalAsString()).isTrue();
        authenticationProvider.setHideCredentialIdNotFoundExceptions(true);
        assertThat(authenticationProvider.isHideCredentialIdNotFoundExceptions()).isTrue();

        authenticationProvider.setUserDetailsService(userDetailsService);
        assertThat(authenticationProvider.getUserDetailsService()).isEqualTo(userDetailsService);
        authenticationProvider.setAuthenticatorService(authenticatorService);
        assertThat(authenticationProvider.getAuthenticatorService()).isEqualTo(authenticatorService);

        authenticationProvider.setPreAuthenticationChecks(preAuthenticationChecker);
        assertThat(authenticationProvider.getPreAuthenticationChecks()).isEqualTo(preAuthenticationChecker);
        authenticationProvider.setPostAuthenticationChecks(postAuthenticationChecker);
        assertThat(authenticationProvider.getPostAuthenticationChecks()).isEqualTo(postAuthenticationChecker);

        authenticationProvider.setExpectedAuthenticationExtensionIds(Collections.singletonList("uvi"));
        assertThat(authenticationProvider.getExpectedAuthenticationExtensionIds()).isEqualTo(Collections.singletonList("uvi"));
    }

    @Test
    public void userDetailsChecker_check_test(){
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
        WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
                "dummy",
                "dummy",
                Collections.singletonList(authenticator),
                Collections.singletonList(grantedAuthority));
        authenticationProvider.getPreAuthenticationChecks().check(userDetails);
    }

    @Test(expected = DisabledException.class)
    public void userDetailsChecker_check_with_disabled_userDetails_test(){
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
        WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
                "dummy",
                "dummy",
                Collections.singletonList(authenticator),
                true,
                false,
                true,
                true,
                true,
                Collections.singletonList(grantedAuthority));
        authenticationProvider.getPreAuthenticationChecks().check(userDetails);
    }

    @Test(expected = AccountExpiredException.class)
    public void userDetailsChecker_check_with_expired_userDetails_test(){
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
        WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
                "dummy",
                "dummy",
                Collections.singletonList(authenticator),
                true,
                true,
                false,
                true,
                true,
                Collections.singletonList(grantedAuthority));
        authenticationProvider.getPreAuthenticationChecks().check(userDetails);
    }

    @Test(expected = CredentialsExpiredException.class)
    public void userDetailsChecker_check_with_credentials_expired_userDetails_test(){
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
        WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
                "dummy",
                "dummy",
                Collections.singletonList(authenticator),
                true,
                true,
                true,
                false,
                true,
                Collections.singletonList(grantedAuthority));
        authenticationProvider.getPostAuthenticationChecks().check(userDetails);
    }

    @Test(expected = LockedException.class)
    public void userDetailsChecker_check_with_locked_userDetails_test(){
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
        WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
                "dummy",
                "dummy",
                Collections.singletonList(authenticator),
                true,
                true,
                true,
                true,
                false,
                Collections.singletonList(grantedAuthority));
        authenticationProvider.getPreAuthenticationChecks().check(userDetails);
    }

    static class UnknownValidationException extends ValidationException {

        UnknownValidationException(String message) {
            super(message);
        }
    }
}
