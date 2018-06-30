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

package net.sharplab.springframework.security.webauthn.request;

import com.webauthn4j.server.ServerProperty;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;


/**
 * WebAuthnAuthenticationRequest
 */
public class WebAuthnAuthenticationRequest implements Serializable {

    //~ Instance fields
    // ================================================================================================
    // user inputs
    private final byte[] credentialId;
    private final byte[] clientDataJSON;
    private final byte[] authenticatorData;
    private final byte[] signature;
    private final String clientExtensionsJSON;
    private final ServerProperty serverProperty;

    public WebAuthnAuthenticationRequest(byte[] credentialId,
                                         byte[] clientDataJSON,
                                         byte[] authenticatorData,
                                         byte[] signature,
                                         String clientExtensionsJSON,
                                         ServerProperty serverProperty) {

        this.credentialId = credentialId;
        this.clientDataJSON = clientDataJSON;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.clientExtensionsJSON = clientExtensionsJSON;
        this.serverProperty = serverProperty;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    public byte[] getClientDataJSON() {
        return clientDataJSON;
    }

    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getSignature() {
        return signature;
    }

    public String getClientExtensionsJSON() {
        return clientExtensionsJSON;
    }

    public ServerProperty getServerProperty() {
        return serverProperty;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnAuthenticationRequest that = (WebAuthnAuthenticationRequest) o;
        return Arrays.equals(credentialId, that.credentialId) &&
                Arrays.equals(clientDataJSON, that.clientDataJSON) &&
                Arrays.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(signature, that.signature) &&
                Objects.equals(clientExtensionsJSON, that.clientExtensionsJSON) &&
                Objects.equals(serverProperty, that.serverProperty);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(clientExtensionsJSON, serverProperty);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(clientDataJSON);
        result = 31 * result + Arrays.hashCode(authenticatorData);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }
}
