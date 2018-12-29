package net.sharplab.springframework.security.webauthn.sample.domain.vo;


import com.webauthn4j.response.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.response.attestation.statement.COSEAlgorithmIdentifier;

public class AndroidKeyAttestationStatementVO implements AttestationStatementVO{

    public static final String FORMAT = "android-key";

    private COSEAlgorithmIdentifier alg;
    private byte[] sig;
    private AttestationCertificatePath x5c;

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

    @Override
    public String getFormat() {
        return FORMAT;
    }
}
