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

package net.sharplab.springframework.security.webauthn.request;

import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.response.client.ClientDataType;
import com.webauthn4j.response.client.Origin;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnAuthenticationRequestTest {

    private CborConverter cborConverter = new CborConverter();

    @Test
    public void equals_hashCode_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] clientDataJSON = TestUtil.createClientDataJSON(ClientDataType.GET);
        byte[] authenticatorData = new AuthenticatorDataConverter(cborConverter).convert(TestUtil.createAuthenticatorData());
        WebAuthnAuthenticationRequest requestA = new WebAuthnAuthenticationRequest(
                new byte[]{0x01, 0x23},
                clientDataJSON,
                authenticatorData,
                new byte[]{0x45, 0x56},
                "",
                new ServerProperty(
                        new Origin("https://example.com"),
                        "example.com",
                        challenge,
                        new byte[]{0x43, 0x21}
                ),
                true
        );
        WebAuthnAuthenticationRequest requestB = new WebAuthnAuthenticationRequest(
                new byte[]{0x01, 0x23},
                clientDataJSON,
                authenticatorData,
                new byte[]{0x45, 0x56},
                "",
                new ServerProperty(
                        new Origin("https://example.com"),
                        "example.com",
                        challenge,
                        new byte[]{0x43, 0x21}
                ),
                true
        );

        assertThat(requestA).isEqualTo(requestB);
        assertThat(requestA).hasSameHashCodeAs(requestB);
    }
}
