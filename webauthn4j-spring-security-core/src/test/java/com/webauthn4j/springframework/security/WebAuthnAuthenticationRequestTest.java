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
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnAuthenticationRequestTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    @Test
    public void getter_test() {
        byte[] clientDataJSON = TestDataUtil.createClientDataJSON(ClientDataType.WEBAUTHN_GET);
        byte[] authenticatorData = new AuthenticatorDataConverter(objectConverter).convert(TestDataUtil.createAuthenticatorData());
        WebAuthnAuthenticationRequest request = new WebAuthnAuthenticationRequest(
                new byte[]{0x01, 0x23},
                clientDataJSON,
                authenticatorData,
                new byte[]{0x45, 0x56},
                ""
        );
        assertThat(request.getCredentialId()).isEqualTo(new byte[]{0x01, 0x23});
        assertThat(request.getClientDataJSON()).isEqualTo(clientDataJSON);
        assertThat(request.getAuthenticatorData()).isEqualTo(authenticatorData);
        assertThat(request.getSignature()).isEqualTo(new byte[]{0x45, 0x56});
        assertThat(request.getClientExtensionsJSON()).isEmpty();
    }

    @Test
    public void equals_hashCode_test() {
        byte[] clientDataJSON = TestDataUtil.createClientDataJSON(ClientDataType.WEBAUTHN_GET);
        byte[] authenticatorData = new AuthenticatorDataConverter(objectConverter).convert(TestDataUtil.createAuthenticatorData());
        WebAuthnAuthenticationRequest requestA = new WebAuthnAuthenticationRequest(
                new byte[]{0x01, 0x23},
                clientDataJSON,
                authenticatorData,
                new byte[]{0x45, 0x56},
                ""
        );
        WebAuthnAuthenticationRequest requestB = new WebAuthnAuthenticationRequest(
                new byte[]{0x01, 0x23},
                clientDataJSON,
                authenticatorData,
                new byte[]{0x45, 0x56},
                ""
        );

        assertThat(requestA)
                .isEqualTo(requestB)
                .hasSameHashCodeAs(requestB);
    }
}
