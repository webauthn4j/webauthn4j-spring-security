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

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnAuthenticationParametersTest {

    @Test
    public void getter_test() {
        Challenge challenge = new DefaultChallenge();
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(new Origin("https://example.com"))
                .rpId("example.com")
                .challenge(challenge)
                .build();
        WebAuthnAuthenticationParameters parameters = new WebAuthnAuthenticationParameters(
                serverProperty,
                true,
                true
        );
        assertThat(parameters.getServerProperty()).isEqualTo(serverProperty);
        assertThat(parameters.isUserVerificationRequired()).isTrue();
        assertThat(parameters.isUserPresenceRequired()).isTrue();
    }

    @Test
    public void equals_hashCode_test() {
        Challenge challenge = new DefaultChallenge();
        WebAuthnAuthenticationParameters parametersA = new WebAuthnAuthenticationParameters(
                ServerProperty.builder()
                        .origin(new Origin("https://example.com"))
                        .rpId("example.com")
                        .challenge(challenge)
                        .build(),
                true,
                true
        );
        WebAuthnAuthenticationParameters parametersB = new WebAuthnAuthenticationParameters(
                ServerProperty.builder()
                        .origin(new Origin("https://example.com"))
                        .rpId("example.com")
                        .challenge(challenge)
                        .build(),
                true,
                true
        );

        assertThat(parametersA)
                .isEqualTo(parametersB)
                .hasSameHashCodeAs(parametersB);
    }
}
