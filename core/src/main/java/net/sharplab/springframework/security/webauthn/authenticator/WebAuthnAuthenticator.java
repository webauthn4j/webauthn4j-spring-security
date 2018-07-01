package net.sharplab.springframework.security.webauthn.authenticator;

import com.webauthn4j.authenticator.AuthenticatorImpl;

import java.util.Objects;

public class WebAuthnAuthenticator extends AuthenticatorImpl {

    //~ Instance fields ================================================================================================
    private String name;

    /**
     * Default constructor
     */
    public WebAuthnAuthenticator() {
        //nop
    }

    /**
     * Constructor
     *
     * @param name authenticator's friendly name
     */
    public WebAuthnAuthenticator(String name) {
        this.setName(name);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        WebAuthnAuthenticator that = (WebAuthnAuthenticator) o;
        return Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {

        return Objects.hash(super.hashCode(), name);
    }
}
