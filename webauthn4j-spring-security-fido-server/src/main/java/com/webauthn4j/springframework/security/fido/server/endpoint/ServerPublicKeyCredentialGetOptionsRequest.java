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

import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;

import java.util.Objects;

public class ServerPublicKeyCredentialGetOptionsRequest implements ServerRequest {
    private String username;
    private final UserVerificationRequirement userVerification;
    private AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput<?>> extensions;

    public ServerPublicKeyCredentialGetOptionsRequest(String username, UserVerificationRequirement userVerification, AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput<?>> extensions) {
        this.username = username;
        this.userVerification = userVerification;
        this.extensions = extensions;
    }

    public ServerPublicKeyCredentialGetOptionsRequest(String username, UserVerificationRequirement userVerification) {
        this.username = username;
        this.userVerification = userVerification;
    }

    public ServerPublicKeyCredentialGetOptionsRequest(String username) {
        this.username = username;
        this.userVerification = UserVerificationRequirement.PREFERRED;
    }

    public ServerPublicKeyCredentialGetOptionsRequest() {
        this.userVerification = UserVerificationRequirement.PREFERRED;
    }

    public String getUsername() {
        return username;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    public AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput<?>> getExtensions() {
        return extensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerPublicKeyCredentialGetOptionsRequest that = (ServerPublicKeyCredentialGetOptionsRequest) o;
        return Objects.equals(username, that.username) &&
                userVerification == that.userVerification &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {

        return Objects.hash(username, userVerification, extensions);
    }
}
