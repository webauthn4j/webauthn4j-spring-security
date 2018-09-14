package net.sharplab.springframework.security.webauthn.options;

public class RelyingParty {

    private String id;
    private String name;

    public RelyingParty(String id, String name) {
        this.id = id;
        this.name = name;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }
}
