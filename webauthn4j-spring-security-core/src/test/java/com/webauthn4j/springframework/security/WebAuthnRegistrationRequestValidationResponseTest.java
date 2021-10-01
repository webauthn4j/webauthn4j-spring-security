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


import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.test.TestDataUtil;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnRegistrationRequestValidationResponseTest {

    @Test
    public void equals_hashCode_test() {
        CollectedClientData clientData = TestDataUtil.createClientData(ClientDataType.WEBAUTHN_CREATE);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = new AuthenticationExtensionsClientOutputs<>();
        Set<AuthenticatorTransport> transports = new HashSet<>();
        WebAuthnRegistrationRequestValidationResponse instanceA =
                new WebAuthnRegistrationRequestValidationResponse(clientData, attestationObject, clientExtensions, transports);
        WebAuthnRegistrationRequestValidationResponse instanceB =
                new WebAuthnRegistrationRequestValidationResponse(clientData, attestationObject, clientExtensions, transports);
        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceB).hasSameHashCodeAs(instanceB);
    }

    @Test
    public void getter_test() {
        CollectedClientData clientData = TestDataUtil.createClientData(ClientDataType.WEBAUTHN_CREATE);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = new AuthenticationExtensionsClientOutputs<>();
        Set<AuthenticatorTransport> transports = new HashSet<>();
        WebAuthnRegistrationRequestValidationResponse instance =
                new WebAuthnRegistrationRequestValidationResponse(clientData, attestationObject, clientExtensions, transports);

        assertThat(instance.getCollectedClientData()).isEqualTo(clientData);
        assertThat(instance.getAttestationObject()).isEqualTo(attestationObject);
        assertThat(instance.getRegistrationExtensionsClientOutputs()).isEqualTo(clientExtensions);
        assertThat(instance.getTransports()).isEqualTo(transports);
    }
}
