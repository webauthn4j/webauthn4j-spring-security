package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import com.webauthn4j.attestation.statement.AttestationCertificatePath;

/**
 * FIDOU2FAttestationStatementVO
 */
public class FIDOU2FAttestationStatementVO implements AttestationStatementVO {

    private static final String FORMAT = "fido-u2f";

    private AttestationCertificatePath x5c;
    private byte[] sig;

    public AttestationCertificatePath getX5c() {
        return x5c;
    }

    public void setX5c(AttestationCertificatePath x5c) {
        this.x5c = x5c;
    }

    public byte[] getSig() {
        return sig;
    }

    public void setSig(byte[] sig) {
        this.sig = sig;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }
}
