package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.response.attestation.AttestationObject;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.response.extension.client.AuthenticationExtensionsClientOutputs;

import java.util.Objects;

public class WebAuthnRegistrationRequestValidationResponse {

    private CollectedClientData collectedClientData;
    private AttestationObject attestationObject;
    private AuthenticationExtensionsClientOutputs registrationExtensionsClientOutputs;

    public WebAuthnRegistrationRequestValidationResponse(CollectedClientData collectedClientData, AttestationObject attestationObject, AuthenticationExtensionsClientOutputs registrationExtensionsClientOutputs) {
        this.collectedClientData = collectedClientData;
        this.attestationObject = attestationObject;
        this.registrationExtensionsClientOutputs = registrationExtensionsClientOutputs;
    }

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public AuthenticationExtensionsClientOutputs getRegistrationExtensionsClientOutputs() {
        return registrationExtensionsClientOutputs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnRegistrationRequestValidationResponse that = (WebAuthnRegistrationRequestValidationResponse) o;
        return Objects.equals(collectedClientData, that.collectedClientData) &&
                Objects.equals(attestationObject, that.attestationObject) &&
                Objects.equals(registrationExtensionsClientOutputs, that.registrationExtensionsClientOutputs);
    }

    @Override
    public int hashCode() {

        return Objects.hash(collectedClientData, attestationObject, registrationExtensionsClientOutputs);
    }
}

