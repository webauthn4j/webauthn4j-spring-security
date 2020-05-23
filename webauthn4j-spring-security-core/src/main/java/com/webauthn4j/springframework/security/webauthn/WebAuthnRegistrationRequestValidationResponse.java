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

package com.webauthn4j.springframework.security.webauthn;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;

import java.util.Objects;

public class WebAuthnRegistrationRequestValidationResponse {

    // ~ Instance fields
    // ================================================================================================

    private final CollectedClientData collectedClientData;
    private final AttestationObject attestationObject;
    private final AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput<?>> registrationExtensionsClientOutputs;

    // ~ Constructors
    // ===================================================================================================

    public WebAuthnRegistrationRequestValidationResponse(CollectedClientData collectedClientData, AttestationObject attestationObject, AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput<?>> registrationExtensionsClientOutputs) {
        this.collectedClientData = collectedClientData;
        this.attestationObject = attestationObject;
        this.registrationExtensionsClientOutputs = registrationExtensionsClientOutputs;
    }

    // ~ Methods
    // ========================================================================================================

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput<?>> getRegistrationExtensionsClientOutputs() {
        return registrationExtensionsClientOutputs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnRegistrationRequestValidationResponse that = (WebAuthnRegistrationRequestValidationResponse) o;
        return Objects.equals(collectedClientData, that.collectedClientData) &&
                Objects.equals(attestationObject, that.attestationObject) &&
                Objects.equals(registrationExtensionsClientOutputs, that.registrationExtensionsClientOutputs);
    }

    @Override
    public int hashCode() {

        return Objects.hash(collectedClientData, attestationObject, registrationExtensionsClientOutputs);
    }
}

