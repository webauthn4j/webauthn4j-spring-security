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
import com.webauthn4j.request.PublicKeyCredentialParameters;
import com.webauthn4j.request.PublicKeyCredentialRpEntity;
import com.webauthn4j.request.extension.client.AuthenticationExtensionsClientInputs;

import java.math.BigInteger;
import java.util.List;

public class ServerPublicKeyCredentialCreationOptionsResponse extends ServerResponseBase {

    private PublicKeyCredentialRpEntity rp;
    private ServerPublicKeyCredentialUserEntity user;
    private String challenge;
    private List<PublicKeyCredentialParameters> pubKeyCredParams;
    private BigInteger timeout;
    private List<ServerPublicKeyCredentialDescriptor> excludeCredentials;
    private AuthenticatorSelectionCriteria authenticatorSelection;
    private AttestationConveyancePreference attestation;
    private AuthenticationExtensionsClientInputs extensions;

    @SuppressWarnings("squid:S00107")
    public ServerPublicKeyCredentialCreationOptionsResponse(
            PublicKeyCredentialRpEntity rp,
            ServerPublicKeyCredentialUserEntity user,
            String challenge,
            List<PublicKeyCredentialParameters> pubKeyCredParams,
            BigInteger timeout,
            List<ServerPublicKeyCredentialDescriptor> excludeCredentials,
            AuthenticatorSelectionCriteria authenticatorSelection,
            AttestationConveyancePreference attestation,
            AuthenticationExtensionsClientInputs extensions) {
        super();

        this.rp = rp;
        this.user = user;
        this.challenge = challenge;
        this.pubKeyCredParams = pubKeyCredParams;
        this.timeout = timeout;
        this.excludeCredentials = excludeCredentials;
        this.authenticatorSelection = authenticatorSelection;
        this.attestation = attestation;
        this.extensions = extensions;
    }

    public ServerPublicKeyCredentialCreationOptionsResponse() {
    }

    public PublicKeyCredentialRpEntity getRp() {
        return rp;
    }

    public ServerPublicKeyCredentialUserEntity getUser() {
        return user;
    }

    public String getChallenge() {
        return challenge;
    }

    public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public BigInteger getTimeout() {
        return timeout;
    }

    public List<ServerPublicKeyCredentialDescriptor> getExcludeCredentials() {
        return excludeCredentials;
    }

    public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public AttestationConveyancePreference getAttestation() {
        return attestation;
    }

    public AuthenticationExtensionsClientInputs getExtensions() {
        return extensions;
    }
}
