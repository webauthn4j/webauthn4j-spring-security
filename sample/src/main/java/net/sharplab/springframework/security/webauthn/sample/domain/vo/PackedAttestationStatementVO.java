package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import com.webauthn4j.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;

import java.util.List;

/**
 * PackedAttestationStatementVO
 */
public class PackedAttestationStatementVO implements AttestationStatementVO {

    private static final String FORMAT = "packed";

    private COSEAlgorithmIdentifier alg;
    private byte[] sig;
    private AttestationCertificatePath x5c;
    private byte[] ecdaaKeyId;

    public COSEAlgorithmIdentifier getAlg() {
        return alg;
    }

    public void setAlg(COSEAlgorithmIdentifier alg) {
        this.alg = alg;
    }

    public byte[] getSig() {
        return sig;
    }

    public void setSig(byte[] sig) {
        this.sig = sig;
    }

    public AttestationCertificatePath getX5c() {
        return x5c;
    }

    public void setX5c(AttestationCertificatePath x5c) {
        this.x5c = x5c;
    }

    public byte[] getEcdaaKeyId() {
        return ecdaaKeyId;
    }

    public void setEcdaaKeyId(byte[] ecdaaKeyId) {
        this.ecdaaKeyId = ecdaaKeyId;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }
}
