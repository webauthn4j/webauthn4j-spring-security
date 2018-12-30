package net.sharplab.springframework.security.webauthn.endpoint;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.AttestationObject;
import net.sharplab.springframework.security.webauthn.authenticator.FidoServerAuthenticatorService;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import org.springframework.security.authentication.InsufficientAuthenticationException;

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

    public FidoServerAttestationResultEndpointFilter(Registry registry, FidoServerAuthenticatorService fidoServerAuthenticatorService){
        super(FILTER_URL, registry.getJsonMapper());
        this.fidoServerAuthenticatorService = fidoServerAuthenticatorService;
        this.attestationObjectConverter = new AttestationObjectConverter(registry);
    }

    @Override
    protected ServerResponse processRequest(HttpServletRequest request) {
        String loginUsername = getLoginUsername();
        if(loginUsername == null){
            throw new InsufficientAuthenticationException("not privileged");
        }
        ServerPublicKeyCredential<ServerAuthenticatorAttestationResponse> credential;
        try {
            credential = objectMapper.readValue(request.getInputStream(),
                    new TypeReference<ServerPublicKeyCredential<ServerAuthenticatorAttestationResponse>>(){});
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        ServerAuthenticatorAttestationResponse response = credential.getResponse();
        AttestationObject attestationObject = attestationObjectConverter.convert(response.getAttestationObject());
        WebAuthnAuthenticator webAuthnAuthenticator =
                new WebAuthnAuthenticator(
                        null,
                        attestationObject.getAuthenticatorData().getAttestedCredentialData(),
                        attestationObject.getAttestationStatement(),
                        attestationObject.getAuthenticatorData().getSignCount());
        fidoServerAuthenticatorService.createAuthenticator(webAuthnAuthenticator);
        byte[] credentialId = attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId();
        fidoServerAuthenticatorService.addAuthenticatorToUser(credentialId, loginUsername);
        return new AttestationResultSuccessResponse();
    }
}
