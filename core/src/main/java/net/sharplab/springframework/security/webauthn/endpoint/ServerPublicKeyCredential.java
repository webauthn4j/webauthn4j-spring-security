package net.sharplab.springframework.security.webauthn.endpoint;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.webauthn4j.request.PublicKeyCredentialType;
import com.webauthn4j.response.extension.client.AuthenticationExtensionsClientOutputs;

import java.util.Objects;

public class ServerPublicKeyCredential<T extends ServerAuthenticatorResponse> {

    private String id;
    private String rawId;
    private PublicKeyCredentialType type;
    private T response;
    private String clientExtensionResults;

    public ServerPublicKeyCredential(
            String id, PublicKeyCredentialType type, T response,
            String clientExtensionResults) {
        this.id = id;
        this.type = type;
        this.response = response;
        this.clientExtensionResults = clientExtensionResults;
    }

    public ServerPublicKeyCredential() {
    }

    @JsonGetter
    public String getId() {
        return id;
    }

    @JsonSetter
    private void setId(String id) {
        this.id = id;
    }

    @JsonGetter
    public String getRawId() {
        return rawId;
    }

    @JsonSetter
    private void setRawId(String rawId) {
        this.rawId = rawId;
    }


    @JsonGetter
    public PublicKeyCredentialType getType() {
        return type;
    }

    @JsonSetter
    private void setType(PublicKeyCredentialType type) {
        this.type = type;
    }

    @JsonGetter
    public T getResponse() {
        return response;
    }

    @JsonSetter
    private void setResponse(T response) {
        this.response = response;
    }

    @JsonGetter
    public String getClientExtensionResults() {
        return clientExtensionResults;
    }

    @JsonSetter
    private void setClientExtensionResults(String clientExtensionResults) {
        this.clientExtensionResults = clientExtensionResults;
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
