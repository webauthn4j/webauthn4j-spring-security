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

package com.webauthn4j.springframework.security.webauthn;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import com.webauthn4j.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;
import com.webauthn4j.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import com.webauthn4j.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import com.webauthn4j.springframework.security.webauthn.util.ExceptionUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * An {@link AuthenticationProvider} implementation for processing {@link WebAuthnAssertionAuthenticationToken}
 */
public class WebAuthnAuthenticationProvider implements AuthenticationProvider {

    //~ Instance fields
    // ================================================================================================

    protected final Log logger = LogFactory.getLog(getClass());

    protected final MessageSourceAccessor messages = SpringSecurityWebAuthnMessageSource.getAccessor();
    private WebAuthnUserDetailsService userDetailsService;
    private final WebAuthnAuthenticatorService authenticatorService;
    private final WebAuthnManager webAuthnManager;
    private boolean forcePrincipalAsString = false;
    private boolean hideCredentialIdNotFoundExceptions = true;
    private UserDetailsChecker preAuthenticationChecks = new DefaultPreAuthenticationChecks();
    private UserDetailsChecker postAuthenticationChecks = new DefaultPostAuthenticationChecks();
    private final GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    // ~ Constructor
    // ========================================================================================================

    public WebAuthnAuthenticationProvider(
            WebAuthnUserDetailsService userDetailsService,
            WebAuthnAuthenticatorService authenticatorService,
            WebAuthnManager webAuthnManager) {

        Assert.notNull(userDetailsService, "userDetailsService must not be null");
        Assert.notNull(authenticatorService, "authenticatorService must not be null");
        Assert.notNull(webAuthnManager, "webAuthnManager must not be null");

        this.userDetailsService = userDetailsService;
        this.authenticatorService = authenticatorService;
        this.webAuthnManager = webAuthnManager;
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * {@inheritDoc}
     */
    @Override
    public Authentication authenticate(Authentication authentication) {
        if (!supports(authentication.getClass())) {
            throw new IllegalArgumentException("Only WebAuthnAssertionAuthenticationToken is supported, " + authentication.getClass() + " was attempted");
        }

        WebAuthnAssertionAuthenticationToken authenticationToken = (WebAuthnAssertionAuthenticationToken) authentication;

        WebAuthnAuthenticationRequest credentials =
                authenticationToken.getCredentials();
        if (credentials == null) {
            logger.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException(messages.getMessage(
                    "WebAuthnAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }

        byte[] credentialId = credentials.getCredentialId();

        WebAuthnUserDetails user = retrieveWebAuthnUserDetails(credentialId);
        Authenticator authenticator = user.getAuthenticators().stream()
                .filter(item -> Arrays.equals(item.getAttestedCredentialData().getCredentialId(), credentialId))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("credentialId doesn't match."));

        preAuthenticationChecks.check(user);
        doAuthenticate(authenticationToken, authenticator, user);
        postAuthenticationChecks.check(user);

        authenticatorService.updateCounter(credentialId, authenticator.getCounter());

        Serializable principalToReturn = user;

        if (forcePrincipalAsString) {
            principalToReturn = user.getUsername();
        }

        WebAuthnAuthenticationToken result = new WebAuthnAuthenticationToken(
                principalToReturn, authenticationToken.getCredentials(),
                authoritiesMapper.mapAuthorities(user.getAuthorities()));
        result.setDetails(authenticationToken.getDetails());

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return WebAuthnAssertionAuthenticationToken.class.isAssignableFrom(authentication);
    }

    void doAuthenticate(WebAuthnAssertionAuthenticationToken authenticationToken, Authenticator authenticator, WebAuthnUserDetails user) {

        WebAuthnAuthenticationRequest credentials = authenticationToken.getCredentials();

        boolean userVerificationRequired = isUserVerificationRequired(user, credentials);

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                credentials.getCredentialId(),
                credentials.getAuthenticatorData(),
                credentials.getClientDataJSON(),
                credentials.getClientExtensionsJSON(),
                credentials.getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                credentials.getServerProperty(),
                authenticator,
                userVerificationRequired,
                credentials.isUserPresenceRequired(),
                credentials.getExpectedAuthenticationExtensionIds()
        );

        try {
            webAuthnManager.validate(authenticationRequest, authenticationParameters);
        } catch (WebAuthnException e) {
            throw ExceptionUtil.wrapWithAuthenticationException(e);
        }

    }

    public boolean isForcePrincipalAsString() {
        return forcePrincipalAsString;
    }

    public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
        this.forcePrincipalAsString = forcePrincipalAsString;
    }

    public boolean isHideCredentialIdNotFoundExceptions() {
        return hideCredentialIdNotFoundExceptions;
    }

    /**
     * By default the <code>WebAuthnAuthenticationProvider</code> throws a
     * <code>BadCredentialsException</code> if a credentialId is not found or the credential is
     * incorrect. Setting this property to <code>false</code> will cause
     * <code>CredentialIdNotFoundException</code>s to be thrown instead for the former. Note
     * this is considered less secure than throwing <code>BadCredentialsException</code>
     * for both exceptions.
     *
     * @param hideCredentialIdNotFoundExceptions set to <code>false</code> if you wish
     *                                           <code>CredentialIdNotFoundException</code>s to be thrown instead of the non-specific
     *                                           <code>BadCredentialsException</code> (defaults to <code>true</code>)
     */
    public void setHideCredentialIdNotFoundExceptions(boolean hideCredentialIdNotFoundExceptions) {
        this.hideCredentialIdNotFoundExceptions = hideCredentialIdNotFoundExceptions;
    }

    protected WebAuthnUserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public void setUserDetailsService(WebAuthnUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    protected UserDetailsChecker getPreAuthenticationChecks() {
        return preAuthenticationChecks;
    }

    /**
     * Sets the policy will be used to verify the status of the loaded
     * <code>UserDetails</code> <em>before</em> validation of the credentials takes place.
     *
     * @param preAuthenticationChecks strategy to be invoked prior to authentication.
     */
    public void setPreAuthenticationChecks(UserDetailsChecker preAuthenticationChecks) {
        this.preAuthenticationChecks = preAuthenticationChecks;
    }

    protected UserDetailsChecker getPostAuthenticationChecks() {
        return postAuthenticationChecks;
    }

    public void setPostAuthenticationChecks(UserDetailsChecker postAuthenticationChecks) {
        this.postAuthenticationChecks = postAuthenticationChecks;
    }

    WebAuthnUserDetails retrieveWebAuthnUserDetails(byte[] credentialId) {
        WebAuthnUserDetails user;
        try {
            user = userDetailsService.loadUserByCredentialId(credentialId);
        } catch (CredentialIdNotFoundException notFound) {
            if (hideCredentialIdNotFoundExceptions) {
                throw new BadCredentialsException(messages.getMessage(
                        "WebAuthnAuthenticationProvider.badCredentials",
                        "Bad credentials"));
            } else {
                throw notFound;
            }
        } catch (Exception repositoryProblem) {
            throw new InternalAuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
        }

        if (user == null) {
            throw new InternalAuthenticationServiceException(
                    "UserDetailsService returned null, which is an interface contract violation");
        }
        return user;
    }

    boolean isUserVerificationRequired(WebAuthnUserDetails user, WebAuthnAuthenticationRequest credentials) {

        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();

        // If current authentication is authenticated and username matches, return false
        if (currentAuthentication != null && currentAuthentication.isAuthenticated() && Objects.equals(currentAuthentication.getName(), user.getUsername())) {
            return false;
        } else {
            return credentials.isUserVerificationRequired();
        }
    }

    private class DefaultPreAuthenticationChecks implements UserDetailsChecker {
        @Override
        public void check(UserDetails user) {
            if (!user.isAccountNonLocked()) {
                logger.debug("User account is locked");

                throw new LockedException(messages.getMessage(
                        "WebAuthnAuthenticationProvider.locked",
                        "User account is locked"));
            }

            if (!user.isEnabled()) {
                logger.debug("User account is disabled");

                throw new DisabledException(messages.getMessage(
                        "WebAuthnAuthenticationProvider.disabled",
                        "User is disabled"));
            }

            if (!user.isAccountNonExpired()) {
                logger.debug("User account is expired");

                throw new AccountExpiredException(messages.getMessage(
                        "WebAuthnAuthenticationProvider.expired",
                        "User account has expired"));
            }
        }
    }

    private class DefaultPostAuthenticationChecks implements UserDetailsChecker {
        @Override
        public void check(UserDetails user) {
            if (!user.isCredentialsNonExpired()) {
                logger.debug("User account credentials have expired");

                throw new CredentialsExpiredException(messages.getMessage(
                        "WebAuthnAuthenticationProvider.credentialsExpired",
                        "User credentials have expired"));
            }
        }
    }
}
