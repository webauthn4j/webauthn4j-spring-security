package net.sharplab.springframework.security.fido.server.endpoint;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.AttestationObject;
import com.webauthn4j.response.client.CollectedClientData;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsImpl;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import net.sharplab.springframework.security.fido.server.validator.ServerPublicKeyCredentialValidator;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Collections;

public class FidoServerAttestationResultEndpointFilter extends ServerEndpointFilterBase {

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/attestation/result";

    private WebAuthnUserDetailsService webAuthnUserDetailsService;
    private AttestationObjectConverter attestationObjectConverter;
    private CollectedClientDataConverter collectedClientDataConverter;
    private WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator;
    private ServerPublicKeyCredentialValidator serverPublicKeyCredentialValidator;

    public FidoServerAttestationResultEndpointFilter(
            Registry registry,
            WebAuthnUserDetailsService webAuthnUserDetailsService,
            WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator){
        super(FILTER_URL, registry);
        this.webAuthnUserDetailsService = webAuthnUserDetailsService;
        this.attestationObjectConverter = new AttestationObjectConverter(registry);
        this.collectedClientDataConverter = new CollectedClientDataConverter(registry);
        this.webAuthnRegistrationRequestValidator = webAuthnRegistrationRequestValidator;
        this.serverPublicKeyCredentialValidator = new ServerPublicKeyCredentialValidator();
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
        serverPublicKeyCredentialValidator.validate(credential);
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
        String loginUsername = serverEndpointFilterUtil.decodeUsername(collectedClientData.getChallenge());
        try{
            webAuthnUserDetailsService.loadUserByUsername(loginUsername);
        }
        catch (UsernameNotFoundException e){
            byte[] userHandle = new byte[0];
            webAuthnUserDetailsService.createUser(new WebAuthnUserDetailsImpl(userHandle, loginUsername, "", Collections.emptyList(), Collections.emptyList()));
        }
        webAuthnUserDetailsService.addAuthenticator(loginUsername, webAuthnAuthenticator);
        return new AttestationResultSuccessResponse();
    }
}
