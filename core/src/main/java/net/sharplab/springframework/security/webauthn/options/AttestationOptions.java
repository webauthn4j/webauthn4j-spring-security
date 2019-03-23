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

package net.sharplab.springframework.security.webauthn.options;


import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import net.sharplab.springframework.security.webauthn.endpoint.WebAuthnPublicKeyCredentialUserEntity;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

@SuppressWarnings("common-java:DuplicatedBlocks")
public class AttestationOptions implements Serializable {

    private PublicKeyCredentialRpEntity relyingParty;
    private WebAuthnPublicKeyCredentialUserEntity user;
    private Challenge challenge;
    private List<PublicKeyCredentialParameters> pubKeyCredParams;
    private BigInteger registrationTimeout;
    private List<String> credentials;
    private AuthenticationExtensionsClientInputs registrationExtensions;

    public AttestationOptions(
            PublicKeyCredentialRpEntity relyingParty,
            WebAuthnPublicKeyCredentialUserEntity user,
            Challenge challenge,
            List<PublicKeyCredentialParameters> pubKeyCredParams,
            BigInteger registrationTimeout,
            List<String> credentials,
            AuthenticationExtensionsClientInputs registrationExtensions) {
        this.relyingParty = relyingParty;
        this.user = user;
        this.challenge = challenge;
        this.pubKeyCredParams = pubKeyCredParams;
        this.registrationTimeout = registrationTimeout;
        this.credentials = credentials;
        this.registrationExtensions = registrationExtensions;
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
     * If authenticated, returns {@link WebAuthnPublicKeyCredentialUserEntity}, which is a serialized form of {@link PublicKeyCredentialUserEntity}
     * Otherwise returns null
     *
     * @return {@link WebAuthnPublicKeyCredentialUserEntity}
     */
    public WebAuthnPublicKeyCredentialUserEntity getUser() {
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

    public BigInteger getRegistrationTimeout() {
        return registrationTimeout;
    }

    public List<String> getCredentials() {
        return credentials;
    }

    public AuthenticationExtensionsClientInputs getRegistrationExtensions() {
        return registrationExtensions;
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
                Objects.equals(registrationTimeout, that.registrationTimeout) &&
                Objects.equals(credentials, that.credentials) &&
                Objects.equals(registrationExtensions, that.registrationExtensions);
    }

    @Override
    public int hashCode() {

        return Objects.hash(relyingParty, user, challenge, pubKeyCredParams, registrationTimeout, credentials, registrationExtensions);
    }
}
