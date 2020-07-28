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

package com.webauthn4j.springframework.security.options;


import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * Options for WebAuthn attestation generation
 */
@SuppressWarnings("common-java:DuplicatedBlocks")
public class AttestationOptions implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private final PublicKeyCredentialRpEntity relyingParty;
    private final PublicKeyCredentialUserEntity user;
    private final Challenge challenge;
    private final List<PublicKeyCredentialParameters> pubKeyCredParams;
    private final Long timeout;
    private final List<PublicKeyCredentialDescriptor> credentials;
    private final AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions;

    // ~ Constructors
    // ===================================================================================================

    public AttestationOptions(
            PublicKeyCredentialRpEntity relyingParty,
            PublicKeyCredentialUserEntity user,
            Challenge challenge,
            List<PublicKeyCredentialParameters> pubKeyCredParams,
            Long timeout,
            List<PublicKeyCredentialDescriptor> credentials,
            AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions) {
        this.relyingParty = relyingParty;
        this.user = user;
        this.challenge = challenge;
        this.pubKeyCredParams = CollectionUtil.unmodifiableList(pubKeyCredParams);
        this.timeout = timeout;
        this.credentials = CollectionUtil.unmodifiableList(credentials);
        this.extensions = extensions;
    }

    /**
     * Returns PublicKeyCredentialRpEntity
     *
     * @return PublicKeyCredentialRpEntity
     */
    public PublicKeyCredentialRpEntity getRelyingParty() {
        return relyingParty;
    }

    /**
     * Return PublicKeyCredentialUserEntity
     * @return {@link PublicKeyCredentialUserEntity}
     */
    public PublicKeyCredentialUserEntity getUser() {
        return user;
    }

    /**
     * Returns {@link Challenge}
     *
     * @return {@link Challenge}
     */
    public Challenge getChallenge() {
        return challenge;
    }

    public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public Long getTimeout() {
        return timeout;
    }

    public List<PublicKeyCredentialDescriptor> getCredentials() {
        return credentials;
    }

    public AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> getExtensions() {
        return extensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AttestationOptions that = (AttestationOptions) o;
        return Objects.equals(relyingParty, that.relyingParty) &&
                Objects.equals(user, that.user) &&
                Objects.equals(challenge, that.challenge) &&
                Objects.equals(pubKeyCredParams, that.pubKeyCredParams) &&
                Objects.equals(timeout, that.timeout) &&
                Objects.equals(credentials, that.credentials) &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {

        return Objects.hash(relyingParty, user, challenge, pubKeyCredParams, timeout, credentials, extensions);
    }
}
