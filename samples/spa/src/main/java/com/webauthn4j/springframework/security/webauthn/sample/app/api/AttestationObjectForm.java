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

package com.webauthn4j.springframework.security.webauthn.sample.app.api;


import com.webauthn4j.data.attestation.AttestationObject;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

/**
 * Form for AttestationObject
 */
public class AttestationObjectForm {

    @NotNull
    @Valid
    private AttestationObject attestationObject;
    @NotNull
    private String attestationObjectBase64;

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public void setAttestationObject(AttestationObject attestationObject) {
        this.attestationObject = attestationObject;
    }

    public String getAttestationObjectBase64() {
        return attestationObjectBase64;
    }

    public void setAttestationObjectBase64(String attestationObjectBase64) {
        this.attestationObjectBase64 = attestationObjectBase64;
    }
}
