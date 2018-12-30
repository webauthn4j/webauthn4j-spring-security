package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.request.AttestationConveyancePreference;
import com.webauthn4j.request.AuthenticatorSelectionCriteria;
import com.webauthn4j.request.PublicKeyCredentialParameters;
import com.webauthn4j.request.PublicKeyCredentialRpEntity;
import com.webauthn4j.request.extension.client.AuthenticationExtensionsClientInputs;

import java.math.BigInteger;
import java.util.List;

public class ServerPublicKeyCredentialCreationOptionsResponse extends ServerResponseBase {

    private PublicKeyCredentialRpEntity rp;
    private ServerPublicKeyCredentialUserEntity user;
    private String challenge;
    private List<PublicKeyCredentialParameters> pubKeyCredParams;
    private BigInteger timeout;
    private List<ServerPublicKeyCredentialDescriptor> excludedCredentials;
    private AuthenticatorSelectionCriteria authenticatorSelection;
    private AttestationConveyancePreference attestation;
    private AuthenticationExtensionsClientInputs extensions;

    public ServerPublicKeyCredentialCreationOptionsResponse(
            PublicKeyCredentialRpEntity rp,
            ServerPublicKeyCredentialUserEntity user,
            String challenge,
            List<PublicKeyCredentialParameters> pubKeyCredParams,
            BigInteger timeout,
            List<ServerPublicKeyCredentialDescriptor> excludedCredentials,
            AuthenticatorSelectionCriteria authenticatorSelection,
            AttestationConveyancePreference attestation,
            AuthenticationExtensionsClientInputs extensions) {
        super();

        this.rp = rp;
        this.user = user;
        this.challenge = challenge;
        this.pubKeyCredParams = pubKeyCredParams;
        this.timeout = timeout;
        this.excludedCredentials = excludedCredentials;
        this.authenticatorSelection = authenticatorSelection;
        this.attestation = attestation;
        this.extensions = extensions;
    }

    public ServerPublicKeyCredentialCreationOptionsResponse(){}

    public PublicKeyCredentialRpEntity getRp() {
        return rp;
    }

    public ServerPublicKeyCredentialUserEntity getUser() {
        return user;
    }

    public String getChallenge() {
        return challenge;
    }

    public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public BigInteger getTimeout() {
        return timeout;
    }

    public List<ServerPublicKeyCredentialDescriptor> getExcludedCredentials() {
        return excludedCredentials;
    }

    public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public AttestationConveyancePreference getAttestation() {
        return attestation;
    }

    public AuthenticationExtensionsClientInputs getExtensions() {
        return extensions;
    }
}
