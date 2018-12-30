package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.request.AuthenticatorTransport;
import com.webauthn4j.request.PublicKeyCredentialType;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

public class ServerPublicKeyCredentialDescriptor implements Serializable {
    private PublicKeyCredentialType type;
    private String id;
    private List<AuthenticatorTransport> transports;

    public ServerPublicKeyCredentialDescriptor(PublicKeyCredentialType type, String id, List<AuthenticatorTransport> transports) {
        this.type = type;
        this.id = id;
        this.transports = transports;
    }

    public ServerPublicKeyCredentialDescriptor(String id) {
        this.type = PublicKeyCredentialType.PUBLIC_KEY;
        this.id = id;
        this.transports = null;
    }

    public ServerPublicKeyCredentialDescriptor(){}

    public PublicKeyCredentialType getType() {
        return type;
    }

    public String getId() {
        return id;
    }

    public List<AuthenticatorTransport> getTransports() {
        return transports;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerPublicKeyCredentialDescriptor that = (ServerPublicKeyCredentialDescriptor) o;
        return type == that.type &&
                Objects.equals(id, that.id) &&
                Objects.equals(transports, that.transports);
    }

    @Override
    public int hashCode() {

        return Objects.hash(type, id, transports);
    }
}
