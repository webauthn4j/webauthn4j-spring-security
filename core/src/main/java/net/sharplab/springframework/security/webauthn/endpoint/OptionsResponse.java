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

package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.request.PublicKeyCredentialParameters;
import com.webauthn4j.request.PublicKeyCredentialRpEntity;
import com.webauthn4j.request.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.response.client.challenge.Challenge;

import java.math.BigInteger;
import java.util.List;

public class OptionsResponse implements Response {

    //~ Instance fields
    // ================================================================================================
    private PublicKeyCredentialRpEntity relyingParty;
    private WebAuthnPublicKeyCredentialUserEntity user;
    private Challenge challenge;
    private List<PublicKeyCredentialParameters> pubKeyCredParams;
    private BigInteger registrationTimeout;
    private BigInteger authenticationTimeout;
    private List<WebAuthnPublicKeyCredentialDescriptor> credentials;
    private AuthenticationExtensionsClientInputs registrationExtensions;
    private AuthenticationExtensionsClientInputs authenticationExtensions;
    private Parameters parameters;

    @SuppressWarnings("squid:S00107")
    public OptionsResponse(
            PublicKeyCredentialRpEntity relyingParty,
            WebAuthnPublicKeyCredentialUserEntity user,
            Challenge challenge,
            List<PublicKeyCredentialParameters> pubKeyCredParams,
            BigInteger registrationTimeout,
            BigInteger authenticationTimeout,
            List<WebAuthnPublicKeyCredentialDescriptor> credentials,
            AuthenticationExtensionsClientInputs registrationExtensions,
            AuthenticationExtensionsClientInputs authenticationExtensions,
            Parameters parameters) {
        super();

        this.relyingParty = relyingParty;
        this.user = user;
        this.challenge = challenge;
        this.pubKeyCredParams = pubKeyCredParams;
        this.registrationTimeout = registrationTimeout;
        this.authenticationTimeout = authenticationTimeout;
        this.credentials = credentials;
        this.registrationExtensions = registrationExtensions;
        this.authenticationExtensions = authenticationExtensions;
        this.parameters = parameters;
    }

    public PublicKeyCredentialRpEntity getRelyingParty() {
        return relyingParty;
    }

    public WebAuthnPublicKeyCredentialUserEntity getUser() {
        return user;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public BigInteger getRegistrationTimeout() {
        return registrationTimeout;
    }

    public BigInteger getAuthenticationTimeout() {
        return authenticationTimeout;
    }

    public List<WebAuthnPublicKeyCredentialDescriptor> getCredentials() {
        return credentials;
    }

    public AuthenticationExtensionsClientInputs getRegistrationExtensions() {
        return registrationExtensions;
    }

    public AuthenticationExtensionsClientInputs getAuthenticationExtensions() {
        return authenticationExtensions;
    }

    public Parameters getParameters() {
        return parameters;
    }

    @Override
    public String getErrorMessage() {
        return null;
    }
}
