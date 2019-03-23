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

package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.data.PublicKeyCredentialType;

import java.util.Objects;

public class ServerPublicKeyCredential<T extends ServerAuthenticatorResponse> {

    private String id;
    private String rawId;
    private PublicKeyCredentialType type;
    private T response;
    private String clientExtensionResults;

    public ServerPublicKeyCredential(
            String id, String rawId, PublicKeyCredentialType type, T response,
            String clientExtensionResults) {
        this.id = id;
        this.rawId = rawId;
        this.type = type;
        this.response = response;
        this.clientExtensionResults = clientExtensionResults;
    }

    public ServerPublicKeyCredential(
            String id, PublicKeyCredentialType type, T response,
            String clientExtensionResults) {
        this.id = id;
        this.rawId = id;
        this.type = type;
        this.response = response;
        this.clientExtensionResults = clientExtensionResults;
    }

    public ServerPublicKeyCredential() {
    }

    public String getId() {
        return id;
    }

    public String getRawId() {
        return rawId;
    }

    public PublicKeyCredentialType getType() {
        return type;
    }

    public T getResponse() {
        return response;
    }

    public String getClientExtensionResults() {
        return clientExtensionResults;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerPublicKeyCredential<?> that = (ServerPublicKeyCredential<?>) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(rawId, that.rawId) &&
                type == that.type &&
                Objects.equals(response, that.response) &&
                Objects.equals(clientExtensionResults, that.clientExtensionResults);
    }

    @Override
    public int hashCode() {

        return Objects.hash(id, rawId, type, response, clientExtensionResults);
    }
}
