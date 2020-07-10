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

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.springframework.security.endpoint.Parameters;
import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class AssertionOptionsTest {

    @Test
    public void equals_hashCode_test() {
        Challenge challenge = new DefaultChallenge();
        Long authenticationTimeout = 1000L;
        String rpId = "localhost";
        List<String> credentialIds = Collections.singletonList("credentialId");
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> authenticationExtensionsClientInputs = new AuthenticationExtensionsClientInputs<>();
        Parameters parameters = new Parameters(
                "username",
                "password",
                "credentialId",
                "clientDataJSON",
                "authenticatorData",
                "signature",
                "clientExtensionsJSON");
        AssertionOptions instanceA = new AssertionOptions(challenge, authenticationTimeout, rpId, credentialIds, authenticationExtensionsClientInputs, parameters);
        AssertionOptions instanceB = new AssertionOptions(challenge, authenticationTimeout, rpId, credentialIds, authenticationExtensionsClientInputs, parameters);

        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);
    }

    @Test
    public void getter_test() {
        Challenge challenge = new DefaultChallenge();
        Long authenticationTimeout = 1000L;
        String rpId = "localhost";
        List<String> credentialIds = Collections.singletonList("credentialId");
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> authenticationExtensionsClientInputs = new AuthenticationExtensionsClientInputs<>();
        Parameters parameters = new Parameters(
                "username",
                "password",
                "credentialId",
                "clientDataJSON",
                "authenticatorData",
                "signature",
                "clientExtensionsJSON");
        AssertionOptions assertionOptions = new AssertionOptions(challenge, authenticationTimeout, rpId, credentialIds, authenticationExtensionsClientInputs, parameters);

        assertThat(assertionOptions.getChallenge()).isEqualTo(challenge);
        assertThat(assertionOptions.getAuthenticationTimeout()).isEqualTo(authenticationTimeout);
        assertThat(assertionOptions.getRpId()).isEqualTo(rpId);
        assertThat(assertionOptions.getCredentials()).isEqualTo(credentialIds);
        assertThat(assertionOptions.getAuthenticationExtensions()).isEqualTo(authenticationExtensionsClientInputs);
        assertThat(assertionOptions.getParameters()).isEqualTo(parameters);
    }
}