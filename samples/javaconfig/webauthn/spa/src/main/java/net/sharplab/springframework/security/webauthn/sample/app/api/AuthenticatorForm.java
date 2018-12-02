package net.sharplab.springframework.security.webauthn.sample.app.api;

public class AuthenticatorForm {

    private Integer id;

    private String credentialId;

    private String name;

    private CollectedClientDataForm clientData;

    private AttestationObjectForm attestationObject;

    private String clientExtensionJSON;

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

    public String getClientExtensionJSON() {
        return clientExtensionJSON;
    }

    public void setClientExtensionJSON(String clientExtensionJSON) {
        this.clientExtensionJSON = clientExtensionJSON;
    }
}
