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
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.exception.CredentialIdNotFoundException;
import com.webauthn4j.springframework.security.util.internal.ExceptionUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.util.Assert;

import java.io.Serializable;

/**
 * An {@link AuthenticationProvider} implementation for processing {@link WebAuthnAssertionAuthenticationToken}
 */
public class WebAuthnAuthenticationProvider implements AuthenticationProvider {

    //~ Instance fields
    // ================================================================================================

    protected final Log logger = LogFactory.getLog(getClass());

    protected final MessageSourceAccessor messages = SpringSecurityWebAuthnMessageSource.getAccessor();
    private final WebAuthnAuthenticatorService authenticatorService;
    private final WebAuthnManager webAuthnManager;
    private boolean hideCredentialIdNotFoundExceptions = true;
    private final GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
    private boolean forcePrincipalAsString;

    // ~ Constructor
    // ========================================================================================================

    public WebAuthnAuthenticationProvider(
            WebAuthnAuthenticatorService authenticatorService,
            WebAuthnManager webAuthnManager) {

        Assert.notNull(authenticatorService, "authenticatorService must not be null");
        Assert.notNull(webAuthnManager, "webAuthnManager must not be null");

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

        WebAuthnAuthenticationRequest credentials = authenticationToken.getCredentials();
        if (credentials == null) {
            logger.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException(messages.getMessage(
                    "WebAuthnAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }

        byte[] credentialId = credentials.getCredentialId();
        WebAuthnAuthenticator webAuthnAuthenticator = retrieveAuthenticator(credentialId);

        doAuthenticate(authenticationToken, webAuthnAuthenticator);
        authenticatorService.updateCounter(credentialId, webAuthnAuthenticator.getCounter());

        Serializable principalToReturn;
        if(forcePrincipalAsString){
            principalToReturn = webAuthnAuthenticator.getUserDetails().getUsername();
        }
        else {
            principalToReturn = webAuthnAuthenticator.getUserDetails();
        }


        WebAuthnAuthenticationToken webAuthnAuthenticationToken = new WebAuthnAuthenticationToken(
                principalToReturn,
                authenticationToken.getCredentials(),
                authoritiesMapper.mapAuthorities(webAuthnAuthenticator.getUserDetails().getAuthorities()));
        webAuthnAuthenticationToken.setDetails(authenticationToken.getDetails());

        return webAuthnAuthenticationToken;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return WebAuthnAssertionAuthenticationToken.class.isAssignableFrom(authentication);
    }

    void doAuthenticate(WebAuthnAssertionAuthenticationToken authenticationToken, WebAuthnAuthenticator webAuthnAuthenticator) {

        WebAuthnAuthenticationRequest request = authenticationToken.getCredentials();
        WebAuthnAuthenticationParameters parameters = authenticationToken.getParameters();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                request.getCredentialId(),
                request.getAuthenticatorData(),
                request.getClientDataJSON(),
                request.getClientExtensionsJSON(),
                request.getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                parameters.getServerProperty(),
                new AuthenticatorImpl(
                        webAuthnAuthenticator.getAttestedCredentialData(),
                        webAuthnAuthenticator.getAttestationStatement(),
                        webAuthnAuthenticator.getCounter(),
                        webAuthnAuthenticator.getTransports(),
                        webAuthnAuthenticator.getClientExtensions(),
                        webAuthnAuthenticator.getAuthenticatorExtensions()),
                parameters.isUserVerificationRequired(),
                parameters.isUserPresenceRequired()
        );

        try {
            webAuthnManager.validate(authenticationRequest, authenticationParameters);
        } catch (WebAuthnException e) {
            throw ExceptionUtil.wrapWithAuthenticationException(e);
        }

    }



    public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
        this.forcePrincipalAsString = forcePrincipalAsString;
    }

    public boolean isForcePrincipalAsString() {
        return forcePrincipalAsString;
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

    WebAuthnAuthenticator retrieveAuthenticator(byte[] credentialId) {
        WebAuthnAuthenticator webAuthnAuthenticator;
        try {
            webAuthnAuthenticator = authenticatorService.loadAuthenticatorByCredentialId(credentialId);
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

        if (webAuthnAuthenticator == null) {
            throw new InternalAuthenticationServiceException(
                    "WebAuthnAuthenticatorService returned null, which is an interface contract violation");
        }
        return webAuthnAuthenticator;
    }

}
