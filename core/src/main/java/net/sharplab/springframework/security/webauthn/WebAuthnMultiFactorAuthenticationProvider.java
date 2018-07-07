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

import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.MultiFactorAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * An {@link AuthenticationProvider} implementation for the first factor(step) of multi factor authentication.
 * Authentication itself is delegated to another {@link AuthenticationProvider}.
 */
public class WebAuthnMultiFactorAuthenticationProvider implements AuthenticationProvider {


    // ~ Instance fields
    // ================================================================================================
    protected MessageSourceAccessor messages = SpringSecurityWebAuthnMessageSource.getAccessor();
    /**
     * {@link AuthenticationProvider} to be delegated
     */
    private AuthenticationProvider authenticationProvider;
    private boolean singleFactorAuthenticationAllowed = true;


    /**
     * Constructor
     * @param authenticationProvider {@link AuthenticationProvider} to be delegated
     */
    public WebAuthnMultiFactorAuthenticationProvider(AuthenticationProvider authenticationProvider) {
        Assert.notNull(authenticationProvider, "Authentication provide must be set");
        this.authenticationProvider = authenticationProvider;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Authentication authenticate(Authentication authentication) {
        if (!supports(authentication.getClass())) {
            throw new IllegalArgumentException("Not supported AuthenticationToken " + authentication.getClass() + " was attempted");
        }

        Authentication result = authenticationProvider.authenticate(authentication);

        if (singleFactorAuthenticationAllowed && result.isAuthenticated() && result.getPrincipal() instanceof WebAuthnUserDetails) {
            WebAuthnUserDetails userDetails = (WebAuthnUserDetails) result.getPrincipal();
            if (userDetails.isSingleFactorAuthenticationAllowed()) {
                return result;
            }
        }

        return new MultiFactorAuthenticationToken(
                result.getPrincipal(),
                result.getCredentials(),
                Collections.emptyList() // result.getAuthorities() is not used as not to inherit authorities from result
        );
    }

    /**
     * Check if single factor authentication is allowed
     * @return true if single factor authentication is allowed
     */
    public boolean isSingleFactorAuthenticationAllowed() {
        return singleFactorAuthenticationAllowed;
    }

    /**
     * Set single factor authentication is allowed
     * @param singleFactorAuthenticationAllowed true if single factor authentication is allowed
     */
    public void setSingleFactorAuthenticationAllowed(boolean singleFactorAuthenticationAllowed) {
        this.singleFactorAuthenticationAllowed = singleFactorAuthenticationAllowed;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return authenticationProvider.supports(authentication);
    }
}
