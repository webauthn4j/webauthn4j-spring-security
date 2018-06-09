package net.sharplab.springframework.security.webauthn.sample.app.web;

import com.webauthn4j.attestation.AttestationObject;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * Form for AttestationObject
 */
public class AttestationObjectForm {

    @NotNull
    @Valid
    private AttestationObject attestationObject;
    @NotNull
    private String attestationObjectBase64;

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public void setAttestationObject(AttestationObject attestationObject) {
        this.attestationObject = attestationObject;
    }

    public String getAttestationObjectBase64() {
        return attestationObjectBase64;
    }

    public void setAttestationObjectBase64(String attestationObjectBase64) {
        this.attestationObjectBase64 = attestationObjectBase64;
    }
}
