package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.request.PublicKeyCredentialType;

import java.util.Objects;

public class ServerPublicKeyCredential<T extends ServerAuthenticatorResponse> {

    private String id;
    private String rawId;
    private PublicKeyCredentialType type;
    private T response;
    private String clientExtensionResults;

    public ServerPublicKeyCredential(
            String id, String rawId, PublicKeyCredentialType type, T response,
            String clientExtensionResults) {
        this.id = id;
        this.rawId =rawId;
        this.type = type;
        this.response = response;
        this.clientExtensionResults = clientExtensionResults;
    }

    public ServerPublicKeyCredential(
            String id, PublicKeyCredentialType type, T response,
            String clientExtensionResults) {
        this.id = id;
        this.rawId = id;
        this.type = type;
        this.response = response;
        this.clientExtensionResults = clientExtensionResults;
    }

    public ServerPublicKeyCredential() {
    }

    public String getId() {
        return id;
    }

    public String getRawId() {
        return rawId;
    }

    public PublicKeyCredentialType getType() {
        return type;
    }

    public T getResponse() {
        return response;
    }

    public String getClientExtensionResults() {
        return clientExtensionResults;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerPublicKeyCredential<?> that = (ServerPublicKeyCredential<?>) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(rawId, that.rawId) &&
                type == that.type &&
                Objects.equals(response, that.response) &&
                Objects.equals(clientExtensionResults, that.clientExtensionResults);
    }

    @Override
    public int hashCode() {

        return Objects.hash(id, rawId, type, response, clientExtensionResults);
    }
}
