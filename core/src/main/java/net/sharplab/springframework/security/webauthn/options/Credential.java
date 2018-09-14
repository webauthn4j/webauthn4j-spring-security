package net.sharplab.springframework.security.webauthn.options;

public class Credential {

    private PublicKeyCredentialType type;
    private String id;

    public Credential(PublicKeyCredentialType type, String id) {
        this.type = type;
        this.id = id;
    }

    public PublicKeyCredentialType getType() {
        return type;
    }

    public String getId() {
        return id;
    }

}
