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
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecord;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * An {@link AuthenticationProvider} implementation for processing {@link WebAuthnAssertionAuthenticationToken}
 */
public class WebAuthnAuthenticationProvider implements AuthenticationProvider {

    //~ Instance fields
    // ================================================================================================

    protected final Log logger = LogFactory.getLog(getClass());

    protected final MessageSourceAccessor messages = SpringSecurityWebAuthnMessageSource.getAccessor();
    private final WebAuthnCredentialRecordService webAuthnCredentialRecordService;
    private final WebAuthnManager webAuthnManager;
    private boolean hideCredentialIdNotFoundExceptions = true;

    // ~ Constructor
    // ========================================================================================================

    public WebAuthnAuthenticationProvider(
            WebAuthnCredentialRecordService webAuthnCredentialRecordService,
            WebAuthnManager webAuthnManager) {

        Assert.notNull(webAuthnCredentialRecordService, "webAuthnCredentialRecordService must not be null");
        Assert.notNull(webAuthnManager, "webAuthnManager must not be null");

        this.webAuthnCredentialRecordService = webAuthnCredentialRecordService;
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
        WebAuthnCredentialRecord webAuthnCredentialRecord = retrieveCredentialRecord(credentialId);

        doAuthenticate(authenticationToken, webAuthnCredentialRecord);
        webAuthnCredentialRecordService.updateCounter(credentialId, webAuthnCredentialRecord.getCounter());

        return createSuccessAuthentication(authenticationToken, webAuthnCredentialRecord);
    }

    protected Authentication createSuccessAuthentication(WebAuthnAssertionAuthenticationToken authenticationToken, WebAuthnCredentialRecord webAuthnCredentialRecord) {
        Object principal = webAuthnCredentialRecord.getUserPrincipal();
        Collection<? extends GrantedAuthority> authorities = null;
        if(principal instanceof UserDetails){
            authorities = ((UserDetails)principal).getAuthorities();
        }

        WebAuthnAuthenticationToken webAuthnAuthenticationToken = new WebAuthnAuthenticationToken(
                principal,
                authenticationToken.getCredentials(),
                authorities);
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

    void doAuthenticate(WebAuthnAssertionAuthenticationToken authenticationToken, WebAuthnCredentialRecord webAuthnCredentialRecord) {

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
                webAuthnCredentialRecord,
                null,
                parameters.isUserVerificationRequired(),
                parameters.isUserPresenceRequired()
        );

        try {
            webAuthnManager.verify(authenticationRequest, authenticationParameters);
        } catch (WebAuthnException e) {
            throw ExceptionUtil.wrapWithAuthenticationException(e);
        }

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

    WebAuthnCredentialRecord retrieveCredentialRecord(byte[] credentialId) {
        WebAuthnCredentialRecord webAuthnCredentialRecord;
        try {
            webAuthnCredentialRecord = webAuthnCredentialRecordService.loadCredentialRecordByCredentialId(credentialId);
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

        if (webAuthnCredentialRecord == null) {
            throw new InternalAuthenticationServiceException(
                    "webAuthnCredentialRecordService returned null, which is an interface contract violation");
        }
        return webAuthnCredentialRecord;
    }

}
