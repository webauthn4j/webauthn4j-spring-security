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

package com.webauthn4j.springframework.security.webauthn.options;

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.springframework.security.webauthn.endpoint.Parameters;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * Options for WebAuthn assertion generation
 */
public class AssertionOptions implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private final Challenge challenge;
    private final Long authenticationTimeout;
    private final String rpId;
    private final List<String> credentials;
    private final AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput<?>> authenticationExtensions;
    private final Parameters parameters;

    // ~ Constructors
    // ===================================================================================================

    public AssertionOptions(
            Challenge challenge,
            Long authenticationTimeout,
            String rpId,
            List<String> credentials,
            AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput<?>> authenticationExtensions,
            Parameters parameters) {
        this.challenge = challenge;
        this.authenticationTimeout = authenticationTimeout;
        this.rpId = rpId;
        this.credentials = CollectionUtil.unmodifiableList(credentials);
        this.authenticationExtensions = authenticationExtensions;
        this.parameters = parameters;
    }

    // ~ Methods
    // ========================================================================================================

    public Challenge getChallenge() {
        return challenge;
    }

    public Long getAuthenticationTimeout() {
        return authenticationTimeout;
    }

    public String getRpId() {
        return rpId;
    }

    public List<String> getCredentials() {
        return credentials;
    }

    public AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput<?>> getAuthenticationExtensions() {
        return authenticationExtensions;
    }

    public Parameters getParameters() {
        return parameters;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AssertionOptions that = (AssertionOptions) o;
        return Objects.equals(challenge, that.challenge) &&
                Objects.equals(authenticationTimeout, that.authenticationTimeout) &&
                Objects.equals(rpId, that.rpId) &&
                Objects.equals(credentials, that.credentials) &&
                Objects.equals(authenticationExtensions, that.authenticationExtensions) &&
                Objects.equals(parameters, that.parameters);
    }

    @Override
    public int hashCode() {

        return Objects.hash(challenge, authenticationTimeout, rpId, credentials, authenticationExtensions, parameters);
    }
}
