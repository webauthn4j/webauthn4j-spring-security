package net.sharplab.springframework.security.webauthn.options;

public class Parameters {

    private String username;
    private String password;
    private String credentialId;
    private String clientData;
    private String authenticatorData;
    private String signature;
    private String clientExtensionsJSON;


    public Parameters(String username, String password, String credentialId, String clientData, String authenticatorData, String signature, String clientExtensionsJSON) {
        this.username = username;
        this.password = password;
        this.credentialId = credentialId;
        this.clientData = clientData;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.clientExtensionsJSON = clientExtensionsJSON;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getClientData() {
        return clientData;
    }

    public String getAuthenticatorData() {
        return authenticatorData;
    }

    public String getSignature() {
        return signature;
    }

    public String getClientExtensionsJSON() {
        return clientExtensionsJSON;
    }
}
