package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.request.AttestationConveyancePreference;
import com.webauthn4j.request.AuthenticatorSelectionCriteria;

public class ServerPublicKeyCredentialCreationOptionsRequest implements ServerRequest {

    private String username;
    private String displayName;
    private AuthenticatorSelectionCriteria authenticatorSelection;
    private AttestationConveyancePreference attestation;

    public ServerPublicKeyCredentialCreationOptionsRequest(
            String username,
            String displayName,
            AuthenticatorSelectionCriteria authenticatorSelection,
            AttestationConveyancePreference attestation) {

        this.username = username;
        this.displayName = displayName;
        this.authenticatorSelection = authenticatorSelection;
        this.attestation = attestation;
    }

    public ServerPublicKeyCredentialCreationOptionsRequest(){}

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public AttestationConveyancePreference getAttestation() {
        return attestation;
    }
}
