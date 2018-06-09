package net.sharplab.springframework.security.webauthn.sample.app.web;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

/**
 * AuthenticatorCreateForm
 */
public class AuthenticatorCreateForm {

    @NotNull
    @NotEmpty
    private String name;

    @NotNull
    @Valid
    private CollectedClientDataForm clientData;

    @NotNull
    @Valid
    private AttestationObjectForm attestationObject;

    @NotNull
    private String clientExtensionsJSON;

    @NotNull
    private Boolean delete;

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

    public String getClientExtensionsJSON() {
        return clientExtensionsJSON;
    }

    public void setClientExtensionsJSON(String clientExtensionsJSON) {
        this.clientExtensionsJSON = clientExtensionsJSON;
    }

    public Boolean getDelete() {
        return delete;
    }

    public void setDelete(Boolean delete) {
        this.delete = delete;
    }
}
