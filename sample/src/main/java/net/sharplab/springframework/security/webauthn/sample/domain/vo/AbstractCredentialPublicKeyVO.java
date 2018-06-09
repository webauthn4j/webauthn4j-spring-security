package net.sharplab.springframework.security.webauthn.sample.domain.vo;


import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.attestation.statement.COSEKeyType;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
@JsonSubTypes({
        @JsonSubTypes.Type(name = "RSACredentialPublicKey", value = RSCredentialPublicKeyVO.class),
        @JsonSubTypes.Type(name = "ECCredentialPublicKey", value = ECCredentialPublicKeyVO.class)
})
public abstract class AbstractCredentialPublicKeyVO implements CredentialPublicKeyVO, Serializable {

    private COSEKeyType keyType;
    private byte[] keyId;
    private int[] keyOpts;
    private byte[] baseIV;

    private COSEAlgorithmIdentifier algorithm;

    public COSEKeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(COSEKeyType keyType) {
        this.keyType = keyType;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public void setKeyId(byte[] keyId) {
        this.keyId = keyId;
    }

    public int[] getKeyOpts() {
        return keyOpts;
    }

    public void setKeyOpts(int[] keyOpts) {
        this.keyOpts = keyOpts;
    }

    public byte[] getBaseIV() {
        return baseIV;
    }

    public void setBaseIV(byte[] baseIV) {
        this.baseIV = baseIV;
    }

    public COSEAlgorithmIdentifier getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(COSEAlgorithmIdentifier algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AbstractCredentialPublicKeyVO that = (AbstractCredentialPublicKeyVO) o;
        return keyType == that.keyType &&
                Arrays.equals(keyId, that.keyId) &&
                Arrays.equals(keyOpts, that.keyOpts) &&
                Arrays.equals(baseIV, that.baseIV) &&
                algorithm == that.algorithm;
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(keyType, algorithm);
        result = 31 * result + Arrays.hashCode(keyId);
        result = 31 * result + Arrays.hashCode(keyOpts);
        result = 31 * result + Arrays.hashCode(baseIV);
        return result;
    }
}
