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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ParametersTest {

    @Test
    public void getter_test(){
        Parameters instance = new Parameters("username", "password",
                "credentialId", "clientDataJSON", "authenticatorData",
                "signature", "clientExtensionsJSON");
        assertThat(instance.getUsername()).isEqualTo("username");
        assertThat(instance.getPassword()).isEqualTo("password");
        assertThat(instance.getCredentialId()).isEqualTo("credentialId");
        assertThat(instance.getClientDataJSON()).isEqualTo("clientDataJSON");
        assertThat(instance.getAuthenticatorData()).isEqualTo("authenticatorData");
        assertThat(instance.getSignature()).isEqualTo("signature");
        assertThat(instance.getClientExtensionsJSON()).isEqualTo("clientExtensionsJSON");
    }

    @Test
    public void equals_hashCode_test() {
        Parameters instanceA = new Parameters("username", "password",
                "credentialId", "clientDataJSON", "authenticatorData",
                "signature", "clientDataJSON");
        Parameters instanceB = new Parameters("username", "password",
                "credentialId", "clientDataJSON", "authenticatorData",
                "signature", "clientDataJSON");

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

}