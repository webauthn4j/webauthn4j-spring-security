package net.sharplab.springframework.security.webauthn.sample.domain.vo;


import com.webauthn4j.response.attestation.statement.JWS;

public class AndroidSafetyNetAttestationStatementVO implements AttestationStatementVO{

    public static final String FORMAT = "android-safetynet";

    private String ver;
    private JWS response;

    public String getVer() {
        return ver;
    }

    public void setVer(String ver) {
        this.ver = ver;
    }

    public JWS getResponse() {
        return response;
    }

    public void setResponse(JWS response) {
        this.response = response;
    }


    @Override
    public String getFormat() {
        return FORMAT;
    }
}
