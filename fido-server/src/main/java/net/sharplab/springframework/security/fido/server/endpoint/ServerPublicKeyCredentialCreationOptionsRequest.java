/*
 *    Copyright 2002-2019 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.request.AttestationConveyancePreference;
import com.webauthn4j.request.AuthenticatorSelectionCriteria;

public class ServerPublicKeyCredentialCreationOptionsRequest implements ServerRequest {

    private String username;
    private String displayName;
    private AuthenticatorSelectionCriteria authenticatorSelection;
    private AttestationConveyancePreference attestation;

    public ServerPublicKeyCredentialCreationOptionsRequest(
            String username,
            String displayName,
            AuthenticatorSelectionCriteria authenticatorSelection,
            AttestationConveyancePreference attestation) {

        this.username = username;
        this.displayName = displayName;
        this.authenticatorSelection = authenticatorSelection;
        this.attestation = attestation;
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
}
