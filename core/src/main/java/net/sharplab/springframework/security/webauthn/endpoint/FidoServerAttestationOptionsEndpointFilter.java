package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.registry.Registry;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.security.authentication.AuthenticationServiceException;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * FIDO Server Endpoint for attestation options processing
 * With this endpoint, non-authorized user can observe requested username existence and his/her credentialId list.
 */
public class FidoServerAttestationOptionsEndpointFilter extends ServerEndpointFilterBase {

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/attestation/options";

    //~ Instance fields
    // ================================================================================================

    private OptionsProvider optionsProvider;

    public FidoServerAttestationOptionsEndpointFilter(Registry registry, OptionsProvider optionsProvider){
        super(FILTER_URL, registry.getJsonMapper());
        this.optionsProvider = optionsProvider;
    }

    @Override
    protected ServerResponse processRequest(HttpServletRequest request) {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        ServerPublicKeyCredentialCreationOptionsRequest serverRequest;
        try {
            serverRequest = objectMapper.readValue(request.getInputStream(), ServerPublicKeyCredentialCreationOptionsRequest.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        String username = serverRequest.getUsername();
        String displayName = serverRequest.getDisplayName();
        AttestationOptions attestationOptions = optionsProvider.getAttestationOptions(request, username, true);
        String userHandle;
        if(attestationOptions.getUser() == null){
            userHandle = Base64UrlUtil.encodeToString(generateUserHandle());
        }
        else {
            userHandle = attestationOptions.getUser().getId();
        }
        ServerPublicKeyCredentialUserEntity user = new ServerPublicKeyCredentialUserEntity(userHandle, username, displayName, null);
        return new ServerPublicKeyCredentialCreationOptionsResponse(
                attestationOptions.getRelyingParty(),
                user,
                Base64UrlUtil.encodeToString(attestationOptions.getChallenge().getValue()),
                attestationOptions.getPubKeyCredParams(),
                attestationOptions.getRegistrationTimeout(),
                attestationOptions.getCredentials(),
                serverRequest.getAuthenticatorSelection(),
                serverRequest.getAttestation(),
                attestationOptions.getRegistrationExtensions());
    }


    private byte[] generateUserHandle(){
        UUID uuid = UUID.randomUUID();
        long hi = uuid.getMostSignificantBits();
        long lo = uuid.getLeastSignificantBits();
        return ByteBuffer.allocate(16).putLong(hi).putLong(lo).array();
    }

}
