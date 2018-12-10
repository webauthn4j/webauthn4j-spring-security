package net.sharplab.springframework.security.webauthn.sample.domain.model;

import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;


/**
 * Authenticator
 */
public class Authenticator extends WebAuthnAuthenticator {

    //~ Instance fields ================================================================================================
    private Integer id;

    public Authenticator() {
        this("Authenticator");
    }

    public Authenticator(String name) {
        super(name);
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }
}
