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

package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.request.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.response.client.challenge.Challenge;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

public class AssertionOptions implements Serializable {

    private Challenge challenge;
    private BigInteger authenticationTimeout;
    private String rpId;
    private List<String> credentials;
    private AuthenticationExtensionsClientInputs authenticationExtensions;
    private Parameters parameters;

    public AssertionOptions(
            Challenge challenge,
            BigInteger authenticationTimeout,
            String rpId,
            List<String> credentials,
            AuthenticationExtensionsClientInputs authenticationExtensions,
            Parameters parameters) {
        this.challenge = challenge;
        this.authenticationTimeout = authenticationTimeout;
        this.rpId = rpId;
        this.credentials = credentials;
        this.authenticationExtensions = authenticationExtensions;
        this.parameters = parameters;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public BigInteger getAuthenticationTimeout() {
        return authenticationTimeout;
    }

    public String getRpId() {
        return rpId;
    }

    public List<String> getCredentials() {
        return credentials;
    }

    public AuthenticationExtensionsClientInputs getAuthenticationExtensions() {
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
