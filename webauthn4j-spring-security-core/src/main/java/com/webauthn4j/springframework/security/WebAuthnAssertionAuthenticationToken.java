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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Objects;

/**
 * An {@link Authentication} implementation for representing WebAuthn assertion like
 * {@link UsernamePasswordAuthenticationToken} for password authentication
 */
public class WebAuthnAssertionAuthenticationToken extends AbstractAuthenticationToken {

    // ~ Instance fields
    // ================================================================================================
    private WebAuthnAuthenticationRequest credentials;
    private final WebAuthnAuthenticationParameters parameters;

    // ~ Constructor
    // ========================================================================================================

    /**
     * This constructor can be safely used by any code that wishes to create a
     * <code>WebAuthnAssertionAuthenticationToken</code>, as the {@link #isAuthenticated()}
     * will return <code>false</code>.
     *
     * @param credentials credentials
     * @param parameters parameters
     * @param authorities authorities
     */
    public WebAuthnAssertionAuthenticationToken(
            WebAuthnAuthenticationRequest credentials,
            WebAuthnAuthenticationParameters parameters,
            Collection<? extends GrantedAuthority> authorities
    ) {
        super(authorities);
        this.credentials = credentials;
        this.parameters = parameters;
        setAuthenticated(false);
    }

    // ~ Methods
    // ========================================================================================================


    /**
     * Always return null
     * @return null
     */
    @Override
    public Object getPrincipal() {
        return null;
    }

    /**
     * @return the stored WebAuthn authentication context
     */
    @Override
    public WebAuthnAuthenticationRequest getCredentials() {
        return credentials;
    }

    public WebAuthnAuthenticationParameters getParameters() {
        return parameters;
    }

    /**
     * This object can never be authenticated, call with true result in exception.
     *
     * @param isAuthenticated only false value allowed
     * @throws IllegalArgumentException if isAuthenticated is true
     */
    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this credential record to trusted");
        }

        super.setAuthenticated(false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        WebAuthnAssertionAuthenticationToken that = (WebAuthnAssertionAuthenticationToken) o;
        return Objects.equals(credentials, that.credentials) &&
                Objects.equals(parameters, that.parameters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), credentials, parameters);
    }
}
