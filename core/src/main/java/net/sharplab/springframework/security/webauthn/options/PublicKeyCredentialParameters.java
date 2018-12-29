package net.sharplab.springframework.security.webauthn.options;


import com.webauthn4j.response.attestation.statement.COSEAlgorithmIdentifier;

public class PublicKeyCredentialParameters {

    private PublicKeyCredentialType type;
    private COSEAlgorithmIdentifier alg;

    public PublicKeyCredentialParameters(PublicKeyCredentialType type, COSEAlgorithmIdentifier alg) {
        this.type = type;
        this.alg = alg;
    }

    public PublicKeyCredentialParameters(){}

    public PublicKeyCredentialType getType() {
        return type;
    }

    public void setType(PublicKeyCredentialType type) {
        this.type = type;
    }

    public COSEAlgorithmIdentifier getAlg() {
        return alg;
    }

    public void setAlg(COSEAlgorithmIdentifier alg) {
        this.alg = alg;
    }


}
