package net.sharplab.springframework.security.fido.server.endpoint;

import java.util.Objects;

public class ServerAuthenticatorAssertionResponse implements ServerAuthenticatorResponse {

    private String clientDataJSON;
    private String authenticatorData;
    private String signature;
    private String userHandle;

    public ServerAuthenticatorAssertionResponse(String clientDataJSON, String authenticatorData, String signature, String userHandle) {
        this.clientDataJSON = clientDataJSON;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.userHandle = userHandle;
    }

    public ServerAuthenticatorAssertionResponse(){}

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public String getAuthenticatorData() {
        return authenticatorData;
    }

    public String getSignature() {
        return signature;
    }

    public String getUserHandle() {
        return userHandle;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerAuthenticatorAssertionResponse that = (ServerAuthenticatorAssertionResponse) o;
        return Objects.equals(clientDataJSON, that.clientDataJSON) &&
                Objects.equals(authenticatorData, that.authenticatorData) &&
                Objects.equals(signature, that.signature) &&
                Objects.equals(userHandle, that.userHandle);
    }

    @Override
    public int hashCode() {

        return Objects.hash(clientDataJSON, authenticatorData, signature, userHandle);
    }
}
