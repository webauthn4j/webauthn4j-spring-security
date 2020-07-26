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

import java.util.Objects;

public class ServerAuthenticatorAssertionResponse implements ServerAuthenticatorResponse {

    private String clientDataJSON;
    private String authenticatorData;
    private String signature;
    private String userHandle;

    public ServerAuthenticatorAssertionResponse(String clientDataJSON, String authenticatorData, String signature, String userHandle) {
        this.clientDataJSON = clientDataJSON;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.userHandle = userHandle;
    }

    public ServerAuthenticatorAssertionResponse() {
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public String getAuthenticatorData() {
        return authenticatorData;
    }

    public String getSignature() {
        return signature;
    }

    public String getUserHandle() {
        return userHandle;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerAuthenticatorAssertionResponse that = (ServerAuthenticatorAssertionResponse) o;
        return Objects.equals(clientDataJSON, that.clientDataJSON) &&
                Objects.equals(authenticatorData, that.authenticatorData) &&
                Objects.equals(signature, that.signature) &&
                Objects.equals(userHandle, that.userHandle);
    }

    @Override
    public int hashCode() {

        return Objects.hash(clientDataJSON, authenticatorData, signature, userHandle);
    }
}
