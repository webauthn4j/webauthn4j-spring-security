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

package com.webauthn4j.springframework.security.fido.server.endpoint;

import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;

import java.util.Objects;

public class ServerPublicKeyCredentialCreationOptionsRequest implements ServerRequest {

    private String username;
    private String displayName;
    private AuthenticatorSelectionCriteria authenticatorSelection;
    private AttestationConveyancePreference attestation;
    private AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions;

    public ServerPublicKeyCredentialCreationOptionsRequest(
            String username,
            String displayName,
            AuthenticatorSelectionCriteria authenticatorSelection,
            AttestationConveyancePreference attestation,
            AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions) {

        this.username = username;
        this.displayName = displayName;
        this.authenticatorSelection = authenticatorSelection;
        this.attestation = attestation;
        this.extensions = extensions;
    }

    public ServerPublicKeyCredentialCreationOptionsRequest() {
    }

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public AttestationConveyancePreference getAttestation() {
        return attestation;
    }

    public AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> getExtensions() {
        return extensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerPublicKeyCredentialCreationOptionsRequest that = (ServerPublicKeyCredentialCreationOptionsRequest) o;
        return Objects.equals(username, that.username) &&
                Objects.equals(displayName, that.displayName) &&
                Objects.equals(authenticatorSelection, that.authenticatorSelection) &&
                attestation == that.attestation &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, displayName, authenticatorSelection, attestation, extensions);
    }
}
