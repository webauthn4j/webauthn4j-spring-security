package net.sharplab.springframework.security.webauthn.endpoint;

import java.util.Objects;

public class WebAuthnUserEntity {

    private String userHandle;
    private String username;

    public WebAuthnUserEntity(String userHandle, String username) {
        this.userHandle = userHandle;
        this.username = username;
    }

    public WebAuthnUserEntity() {
    }

    public String getUserHandle() {
        return userHandle;
    }

    public String getUsername() {
        return username;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnUserEntity that = (WebAuthnUserEntity) o;
        return Objects.equals(userHandle, that.userHandle) &&
                Objects.equals(username, that.username);
    }

    @Override
    public int hashCode() {

        return Objects.hash(userHandle, username);
    }
}
