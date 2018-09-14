package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter.CredentialPublicKeyVOConverter;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Embeddable;
import java.io.Serializable;

/**
 * AttestedCredentialDataVO
 */
@Embeddable
public class AttestedCredentialDataVO implements Serializable {

    @Column(columnDefinition = "blob")
    private byte[] aaGuid;

    @Column(columnDefinition = "blob")
    private byte[] credentialId;

    @Column(columnDefinition = "text")
    @Convert(converter = CredentialPublicKeyVOConverter.class)
    private CredentialPublicKeyVO credentialPublicKey;

    public byte[] getAaGuid() {
        return aaGuid;
    }

    public void setAaGuid(byte[] aaGuid) {
        this.aaGuid = aaGuid;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(byte[] credentialId) {
        this.credentialId = credentialId;
    }

    public CredentialPublicKeyVO getCredentialPublicKey() {
        return credentialPublicKey;
    }

    public void setCredentialPublicKey(CredentialPublicKeyVO credentialPublicKey) {
        this.credentialPublicKey = credentialPublicKey;
    }
}
