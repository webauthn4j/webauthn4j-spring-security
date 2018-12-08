package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.extension.client.ClientExtensionOutput;

import java.util.Map;
import java.util.Objects;

public class WebAuthnRegistrationRequestValidationResponse {

    private CollectedClientData collectedClientData;
    private AttestationObject attestationObject;
    private Map<String, ClientExtensionOutput> clientExtensionOutputs;

    public WebAuthnRegistrationRequestValidationResponse(CollectedClientData collectedClientData, AttestationObject attestationObject, Map<String, ClientExtensionOutput> clientExtensionOutputs) {
        this.collectedClientData = collectedClientData;
        this.attestationObject = attestationObject;
        this.clientExtensionOutputs = clientExtensionOutputs;
    }

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public Map<String, ClientExtensionOutput> getClientExtensionOutputs() {
        return clientExtensionOutputs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnRegistrationRequestValidationResponse that = (WebAuthnRegistrationRequestValidationResponse) o;
        return Objects.equals(collectedClientData, that.collectedClientData) &&
                Objects.equals(attestationObject, that.attestationObject) &&
                Objects.equals(clientExtensionOutputs, that.clientExtensionOutputs);
    }

    @Override
    public int hashCode() {

        return Objects.hash(collectedClientData, attestationObject, clientExtensionOutputs);
    }
}

