package net.sharplab.springframework.security.webauthn.endpoint;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.AttestationObject;
import com.webauthn4j.response.client.CollectedClientData;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.authenticator.FidoServerAuthenticatorService;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import org.springframework.security.authentication.AuthenticationServiceException;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UncheckedIOException;

public class FidoServerAttestationResultEndpointFilter extends ServerEndpointFilterBase {

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/attestation/result";

    private FidoServerAuthenticatorService fidoServerAuthenticatorService;
    private AttestationObjectConverter attestationObjectConverter;
    private CollectedClientDataConverter collectedClientDataConverter;
    private WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator;

    public FidoServerAttestationResultEndpointFilter(
            Registry registry,
            FidoServerAuthenticatorService fidoServerAuthenticatorService,
            WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator){
        super(FILTER_URL, registry);
        this.fidoServerAuthenticatorService = fidoServerAuthenticatorService;
        this.attestationObjectConverter = new AttestationObjectConverter(registry);
        this.collectedClientDataConverter = new CollectedClientDataConverter(registry);
        this.webAuthnRegistrationRequestValidator = webAuthnRegistrationRequestValidator;

    }

    @Override
    protected ServerResponse processRequest(HttpServletRequest request) {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        ServerPublicKeyCredential<ServerAuthenticatorAttestationResponse> credential;
        try {
            credential = registry.getJsonMapper().readValue(request.getInputStream(),
                    new TypeReference<ServerPublicKeyCredential<ServerAuthenticatorAttestationResponse>>(){});
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        ServerAuthenticatorAttestationResponse response = credential.getResponse();
        AttestationObject attestationObject = attestationObjectConverter.convert(response.getAttestationObject());
        CollectedClientData collectedClientData = collectedClientDataConverter.convert(response.getClientDataJSON());
        webAuthnRegistrationRequestValidator.validate(
                request,
                response.getClientDataJSON(),
                response.getAttestationObject(),
                credential.getClientExtensionResults());

        WebAuthnAuthenticator webAuthnAuthenticator =
                new WebAuthnAuthenticator(
                        "Authenticator",
                        attestationObject.getAuthenticatorData().getAttestedCredentialData(),
                        attestationObject.getAttestationStatement(),
                        attestationObject.getAuthenticatorData().getSignCount());
        fidoServerAuthenticatorService.createAuthenticator(webAuthnAuthenticator);
        byte[] credentialId = attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId();
        String loginUsername = serverEndpointFilterUtil.decodeUsername(collectedClientData.getChallenge());
        fidoServerAuthenticatorService.addAuthenticatorToUser(credentialId, loginUsername);
        return new AttestationResultSuccessResponse();
    }
}
