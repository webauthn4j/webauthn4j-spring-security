package net.sharplab.springframework.security.webauthn.sample.domain.entity;

import net.sharplab.springframework.security.webauthn.sample.domain.vo.AttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AttestedCredentialDataVO;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter.AttestationStatementVOConverter;

import javax.persistence.*;
import java.io.Serializable;

/**
 * AuthenticatorEntity
 */
@Entity
@Table(name = "m_authenticator")
public class AuthenticatorEntity implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String name;

    @ManyToOne
    private UserEntity user;

    @Column(columnDefinition = "blob")
    private byte[] rpIdHash;

    private long counter;

    @Embedded
    private AttestedCredentialDataVO attestedCredentialData;

    //TODO: extensions?

    public String getFormat() {
        return attestationStatement.getFormat();
    }

    @Column(columnDefinition = "text")
    @Convert(converter = AttestationStatementVOConverter.class)
    private AttestationStatementVO attestationStatement;

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

    public byte[] getRpIdHash() {
        return rpIdHash;
    }

    public void setRpIdHash(byte[] rpIdHash) {
        this.rpIdHash = rpIdHash;
    }

    public long getCounter() {
        return counter;
    }

    public void setCounter(long counter) {
        this.counter = counter;
    }

    public AttestedCredentialDataVO getAttestedCredentialData() {
        return attestedCredentialData;
    }

    public void setAttestedCredentialData(AttestedCredentialDataVO attestedCredentialData) {
        this.attestedCredentialData = attestedCredentialData;
    }

    public AttestationStatementVO getAttestationStatement() {
        return attestationStatement;
    }

    public void setAttestationStatement(AttestationStatementVO attestationStatement) {
        this.attestationStatement = attestationStatement;
    }
}
