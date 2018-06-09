package net.sharplab.springframework.security.webauthn.sample.domain.model;

import com.webauthn4j.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.attestation.statement.AttestationStatement;


/**
 * Authenticator
 */
public class Authenticator implements com.webauthn4j.authenticator.Authenticator {

    //~ Instance fields ================================================================================================
    private Integer id;
    private String name;

    private byte[] rpIdHash;
    private long counter;
    private AttestedCredentialData attestedCredentialData;
    private AttestationStatement attestationStatement;

    /**
     * Constructor
     */
    public Authenticator() {
        //nop
    }

    /**
     * Constructor
     *
     * @param name authenticator's friendly name
     */
    public Authenticator(String name) {
        this.setName(name);
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public byte[] getRpIdHash() {
        return rpIdHash;
    }

    public void setRpIdHash(byte[] rpIdHash) {
        this.rpIdHash = rpIdHash;
    }

    @Override
    public long getCounter() {
        return counter;
    }

    @Override
    public void setCounter(long counter) {
        this.counter = counter;
    }

    @Override
    public AttestedCredentialData getAttestedCredentialData() {
        return attestedCredentialData;
    }

    public void setAttestedCredentialData(AttestedCredentialData attestedCredentialData) {
        this.attestedCredentialData = attestedCredentialData;
    }

    @Override
    public AttestationStatement getAttestationStatement() {
        return attestationStatement;
    }

    public void setAttestationStatement(AttestationStatement attestationStatement) {
        this.attestationStatement = attestationStatement;
    }
}
