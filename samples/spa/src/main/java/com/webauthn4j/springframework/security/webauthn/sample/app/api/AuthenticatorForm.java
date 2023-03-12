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

import com.webauthn4j.springframework.security.webauthn.sample.app.api.validator.AuthenticatorFormValidator;

import jakarta.validation.constraints.NotEmpty;
import java.util.Set;

public class AuthenticatorForm {

    /**
     * correlation validation is implemented in {@link AuthenticatorFormValidator}
     */
    private Integer id;

    private String credentialId;

    @NotEmpty
    private String name;

    /**
     * correlation validation is implemented in {@link AuthenticatorFormValidator}
     */
    private CollectedClientDataForm clientData;

    /**
     * correlation validation is implemented in {@link AuthenticatorFormValidator}
     */
    private AttestationObjectForm attestationObject;

    private Set<String> transports;

    /**
     * correlation validation is implemented in {@link AuthenticatorFormValidator}
     */
    private String clientExtensionsJSON;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public CollectedClientDataForm getClientData() {
        return clientData;
    }

    public void setClientData(CollectedClientDataForm clientData) {
        this.clientData = clientData;
    }

    public AttestationObjectForm getAttestationObject() {
        return attestationObject;
    }

    public void setAttestationObject(AttestationObjectForm attestationObject) {
        this.attestationObject = attestationObject;
    }

    public Set<String> getTransports() {
        return transports;
    }

    public void setTransports(Set<String> transports) {
        this.transports = transports;
    }

    public String getClientExtensionsJSON() {
        return clientExtensionsJSON;
    }

    public void setClientExtensionsJSON(String clientExtensionsJSON) {
        this.clientExtensionsJSON = clientExtensionsJSON;
    }
}
