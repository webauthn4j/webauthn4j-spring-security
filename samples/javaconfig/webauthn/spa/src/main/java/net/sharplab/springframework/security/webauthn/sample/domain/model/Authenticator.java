package net.sharplab.springframework.security.webauthn.sample.domain.model;

import com.webauthn4j.response.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.response.attestation.statement.AttestationStatement;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;


/**
 * Authenticator
 */
public class Authenticator extends WebAuthnAuthenticator {

    //~ Instance fields ================================================================================================
    private Integer id;

    public Authenticator() {
        this("Authenticator", null, null, 0);
    }

    public Authenticator(String name, AttestedCredentialData attestedCredentialData, AttestationStatement attestationStatement, long counter) {
        super(name, attestedCredentialData, attestationStatement, counter);
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }
}
