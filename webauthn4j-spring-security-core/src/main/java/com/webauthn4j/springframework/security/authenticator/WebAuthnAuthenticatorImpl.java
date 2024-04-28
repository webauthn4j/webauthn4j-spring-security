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
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;

import java.io.Serializable;
import java.util.Objects;
import java.util.Set;

/**
 * An implementation of {@link WebAuthnAuthenticator}
 */
public class WebAuthnAuthenticatorImpl extends CredentialRecordImpl implements WebAuthnAuthenticator {

    // ~ Instance fields
    // ================================================================================================
    private String name;
    private Serializable userPrincipal;

    // ~ Constructor
    // ========================================================================================================


    /**
     * Constructor
     *
     * @param name                    authenticator's friendly name
     * @param userPrincipal           principal that represents user
     * @param attestationObject       attestation object
     * @param clientData              client data
     * @param clientExtensions        client extensions
     * @param transports              transports
     */
    public WebAuthnAuthenticatorImpl(
            String name,
            Serializable userPrincipal,
            AttestationObject attestationObject,
            CollectedClientData clientData,
            AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
            Set<AuthenticatorTransport> transports) {
        super(attestationObject, clientData, clientExtensions, transports);
        this.name = name;
        this.userPrincipal = userPrincipal;
    }

    /**
     * Constructor
     *
     * @param name                    authenticator's friendly name
     * @param userPrincipal           principal that represents user
     * @param uvInitialized           uv initialized
     * @param backupEligible          backup eligible
     * @param backupState             backup state
     * @param counter                 counter
     * @param attestedCredentialData  attested credential data
     * @param authenticatorExtensions authenticator extensions
     * @param clientData              client data
     * @param clientExtensions        client extensions
     * @param transports              transports
     */
    public WebAuthnCredentialRecordImpl(
            String name,
            Serializable userPrincipal,
            AttestationStatement attestationStatement,
            Boolean uvInitialized,
            Boolean backupEligible,
            Boolean backupState,
            long counter,
            AttestedCredentialData attestedCredentialData,
            AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions,
            CollectedClientData clientData,
            AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
            Set<AuthenticatorTransport> transports) {
        super(attestationStatement, uvInitialized, backupEligible, backupState, counter, attestedCredentialData, authenticatorExtensions, clientData, clientExtensions, transports);
        this.name = name;
        this.userPrincipal = userPrincipal;
    }

    /**
     * Constructor
     * This constructor is left for backward-compatibility with WebAuthnAuthenticatorImpl
     *
     * @param name                    authenticator's friendly name
     * @param userPrincipal           principal that represents user
     * @param attestedCredentialData  attested credential data
     * @param attestationStatement    attestation statement
     * @param counter                 counter
     * @param transports              transports
     * @param clientExtensions        client extensions
     * @param authenticatorExtensions authenticator extensions
     */
    @SuppressWarnings("java:S107")
    public WebAuthnAuthenticatorImpl(
            String name,
            Serializable userPrincipal,
            AttestedCredentialData attestedCredentialData,
            AttestationStatement attestationStatement,
            long counter,
            Set<AuthenticatorTransport> transports,
            AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
            AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions) {
        super(attestationStatement, null, null, null, counter, attestedCredentialData, authenticatorExtensions, null, clientExtensions, transports);
        this.setName(name);
        this.userPrincipal = userPrincipal;
    }

    /**
     * Constructor
     * This constructor is left for backward-compatibility with WebAuthnAuthenticatorImpl
     *
     * @param name                    authenticator's friendly name
     * @param userPrincipal           principal that represents user
     * @param attestedCredentialData  attested credential data
     * @param attestationStatement    attestation statement
     * @param counter                 counter
     */
    public WebAuthnAuthenticatorImpl(
            String name,
            Serializable userPrincipal,
            AttestedCredentialData attestedCredentialData,
            AttestationStatement attestationStatement,
            long counter) {
        this(name, userPrincipal, attestedCredentialData, attestationStatement, counter, null, null, null);
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

    /**
     * {@inheritDoc}
     */
    @Override
    public Serializable getUserPrincipal() {
        return userPrincipal;
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
