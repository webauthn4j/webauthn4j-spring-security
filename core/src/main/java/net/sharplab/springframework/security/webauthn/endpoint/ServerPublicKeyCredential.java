package net.sharplab.springframework.security.webauthn.endpoint;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.webauthn4j.request.PublicKeyCredentialType;
import com.webauthn4j.response.extension.client.AuthenticationExtensionsClientOutputs;

import java.util.Objects;

public class ServerPublicKeyCredential<T extends ServerAuthenticatorResponse> {

    private String id;
    private PublicKeyCredentialType type = PublicKeyCredentialType.PUBLIC_KEY;
    private T response;
    private AuthenticationExtensionsClientOutputs clientExtensionResults;

    public ServerPublicKeyCredential(
            String id, PublicKeyCredentialType type, T response,
            AuthenticationExtensionsClientOutputs clientExtensionResults) {
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
        return id;
    }

    @JsonSetter
    private void setRawId(String rawId) {
        this.id = rawId;
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
    public AuthenticationExtensionsClientOutputs getClientExtensionResults() {
        return clientExtensionResults;
    }

    @JsonSetter
    private void setClientExtensionResults(AuthenticationExtensionsClientOutputs clientExtensionResults) {
        this.clientExtensionResults = clientExtensionResults;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerPublicKeyCredential that = (ServerPublicKeyCredential) o;
        return Objects.equals(id, that.id) &&
                type == that.type &&
                Objects.equals(response, that.response) &&
                Objects.equals(clientExtensionResults, that.clientExtensionResults);
    }

    @Override
    public int hashCode() {

        return Objects.hash(id, type, response, clientExtensionResults);
    }
}
