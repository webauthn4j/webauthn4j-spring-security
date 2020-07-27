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

package com.webauthn4j.springframework.security.endpoint;

import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.util.CollectionUtil;

import java.util.List;

/**
 * Success response of {@link AttestationOptionsEndpointFilter}
 */
public class AssertionOptionsResponse implements Response {

    // ~ Instance fields
    // ================================================================================================
    private final Challenge challenge;
    private final Long timeout;
    private final List<PublicKeyCredentialDescriptor> credentials;
    private final AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions;
    private final Parameters parameters;

    // ~ Constructors
    // ===================================================================================================

    @SuppressWarnings("squid:S00107")
    public AssertionOptionsResponse(
            Challenge challenge,
            Long timeout,
            List<PublicKeyCredentialDescriptor> credentials,
            AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions,
            Parameters parameters) {
        super();

        this.challenge = challenge;
        this.timeout = timeout;
        this.credentials = CollectionUtil.unmodifiableList(credentials);
        this.extensions = extensions;
        this.parameters = parameters;
    }

    // ~ Methods
    // ========================================================================================================

    public Challenge getChallenge() {
        return this.challenge;
    }

    public Long getTimeout() {
        return this.timeout;
    }

    public List<PublicKeyCredentialDescriptor> getCredentials() {
        return this.credentials;
    }

    public AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> getExtensions() {
        return this.extensions;
    }

    public Parameters getParameters() {
        return parameters;
    }

    @Override
    public String getErrorMessage() {
        return null;
    }
}
