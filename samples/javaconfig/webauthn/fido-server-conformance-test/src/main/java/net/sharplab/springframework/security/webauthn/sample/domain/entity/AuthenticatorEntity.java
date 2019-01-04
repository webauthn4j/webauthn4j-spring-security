package net.sharplab.springframework.security.webauthn.sample.domain.entity;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.response.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.response.attestation.statement.AttestationStatement;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter.AttestationStatementConverter;

import javax.persistence.*;

/**
 * Authenticator model
 */
@Entity
@Table(name = "m_authenticator")
public class AuthenticatorEntity implements Authenticator {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String name;

    @ManyToOne
    private UserEntity user;

    private long counter;

    @Embedded
    private AttestedCredentialData attestedCredentialData;

    //TODO: extensions?
    @Column(columnDefinition = "text")
    @Convert(converter = AttestationStatementConverter.class)
    private AttestationStatement attestationStatement;

    public String getFormat() {
        return attestationStatement.getFormat();
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

    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    public long getCounter() {
        return counter;
    }

    public void setCounter(long counter) {
        this.counter = counter;
    }

    public AttestedCredentialData getAttestedCredentialData() {
        return attestedCredentialData;
    }

    public void setAttestedCredentialData(AttestedCredentialData attestedCredentialData) {
        this.attestedCredentialData = attestedCredentialData;
    }

    public AttestationStatement getAttestationStatement() {
        return attestationStatement;
    }

    public void setAttestationStatement(AttestationStatement attestationStatement) {
        this.attestationStatement = attestationStatement;
    }
}
