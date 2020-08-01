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

package com.webauthn4j.springframework.security.authenticator;

import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Objects;

/**
 * An implementation of {@link WebAuthnAuthenticator}
 */
public class WebAuthnAuthenticatorImpl extends AuthenticatorImpl implements WebAuthnAuthenticator { //TODO: add more members

    // ~ Instance fields
    // ================================================================================================
    private String name;
    private UserDetails userPrincipal;

    // ~ Constructor
    // ========================================================================================================

    /**
     * Constructor
     *
     * @param name                   authenticator's friendly name
     * @param attestedCredentialData attested credential data
     * @param attestationStatement   attestation statement
     * @param counter                counter
     */
    public WebAuthnAuthenticatorImpl(String name, AttestedCredentialData attestedCredentialData, AttestationStatement attestationStatement, long counter) {
        super(attestedCredentialData, attestationStatement, counter);
        this.setName(name);
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * {@inheritDoc}
     */
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public UserDetails getUserPrincipal() {
        return userPrincipal;
    }

    public void setUserPrincipal(UserDetails userPrincipal) {
        this.userPrincipal = userPrincipal;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        WebAuthnAuthenticatorImpl that = (WebAuthnAuthenticatorImpl) o;
        return Objects.equals(name, that.name);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {

        return Objects.hash(super.hashCode(), name);
    }
}
