package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.request.PublicKeyCredentialEntity;

import java.util.Objects;

public class ServerPublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {

    private String id;
    private String displayName;

    public ServerPublicKeyCredentialUserEntity(String id, String name, String displayName, String icon) {
        super(name, icon);
        this.id = id;
        this.displayName = displayName;
    }

    public ServerPublicKeyCredentialUserEntity(String id, String name, String displayName) {
        super(name);
        this.id = id;
        this.displayName = displayName;
    }

    public ServerPublicKeyCredentialUserEntity() {
    }

    public String getId() {
        return id;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerPublicKeyCredentialUserEntity that = (ServerPublicKeyCredentialUserEntity) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(displayName, that.displayName);
    }

    @Override
    public int hashCode() {

        return Objects.hash(id, displayName);
    }
}
