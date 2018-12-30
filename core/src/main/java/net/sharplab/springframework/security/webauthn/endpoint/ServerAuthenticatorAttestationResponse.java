package net.sharplab.springframework.security.webauthn.endpoint;

import java.util.Objects;

public class ServerAuthenticatorAttestationResponse implements ServerAuthenticatorResponse {

    private String clientDataJSON;
    private String attestationObject;

    public ServerAuthenticatorAttestationResponse(String clientDataJSON, String attestationObject) {
        this.clientDataJSON = clientDataJSON;
        this.attestationObject = attestationObject;
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public String getAttestationObject() {
        return attestationObject;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerAuthenticatorAttestationResponse that = (ServerAuthenticatorAttestationResponse) o;
        return Objects.equals(clientDataJSON, that.clientDataJSON) &&
                Objects.equals(attestationObject, that.attestationObject);
    }

    @Override
    public int hashCode() {

        return Objects.hash(clientDataJSON, attestationObject);
    }
}
