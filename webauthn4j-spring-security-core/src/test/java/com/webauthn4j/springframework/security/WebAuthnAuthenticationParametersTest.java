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

package com.webauthn4j.springframework.security;

import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestDataUtil;
import org.junit.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnAuthenticationParametersTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    @Test
    public void getter_test() {
        Challenge challenge = new DefaultChallenge();
        ServerProperty serverProperty = new ServerProperty(
                new Origin("https://example.com"),
                "example.com",
                challenge,
                new byte[]{0x43, 0x21}
        );
        WebAuthnAuthenticationParameters parameters = new WebAuthnAuthenticationParameters(
                serverProperty,
                true,
                true,
                Collections.singletonList("uvi")
        );
        assertThat(parameters.getServerProperty()).isEqualTo(serverProperty);
        assertThat(parameters.isUserVerificationRequired()).isTrue();
        assertThat(parameters.isUserPresenceRequired()).isTrue();
        assertThat(parameters.getExpectedAuthenticationExtensionIds()).isEqualTo(Collections.singletonList("uvi"));
    }

    @Test
    public void equals_hashCode_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] clientDataJSON = TestDataUtil.createClientDataJSON(ClientDataType.GET);
        byte[] authenticatorData = new AuthenticatorDataConverter(objectConverter).convert(TestDataUtil.createAuthenticatorData());
        WebAuthnAuthenticationParameters parametersA = new WebAuthnAuthenticationParameters(
                new ServerProperty(
                        new Origin("https://example.com"),
                        "example.com",
                        challenge,
                        new byte[]{0x43, 0x21}
                ),
                true,
                true,
                Collections.singletonList("uvi")
        );
        WebAuthnAuthenticationParameters parametersB = new WebAuthnAuthenticationParameters(
                new ServerProperty(
                        new Origin("https://example.com"),
                        "example.com",
                        challenge,
                        new byte[]{0x43, 0x21}
                ),
                true,
                true,
                Collections.singletonList("uvi")
        );

        assertThat(parametersA)
                .isEqualTo(parametersB)
                .hasSameHashCodeAs(parametersB);
    }
}
