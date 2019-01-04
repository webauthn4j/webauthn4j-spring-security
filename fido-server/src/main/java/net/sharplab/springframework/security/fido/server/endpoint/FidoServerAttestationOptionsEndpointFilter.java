package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.webauthn.endpoint.AttestationOptions;
import net.sharplab.springframework.security.webauthn.endpoint.OptionsProvider;
import org.springframework.security.authentication.AuthenticationServiceException;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

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
        super(FILTER_URL, registry);
        this.optionsProvider = optionsProvider;
    }

    @Override
    protected ServerResponse processRequest(HttpServletRequest request) {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        ServerPublicKeyCredentialCreationOptionsRequest serverRequest;
        try {
            serverRequest = registry.getJsonMapper().readValue(request.getInputStream(), ServerPublicKeyCredentialCreationOptionsRequest.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        String username = serverRequest.getUsername();
        String displayName = serverRequest.getDisplayName();
        Challenge challenge = serverEndpointFilterUtil.encodeUsername(new DefaultChallenge(), username);
        AttestationOptions attestationOptions = optionsProvider.getAttestationOptions(request, username, challenge);
        String userHandle;
        if(attestationOptions.getUser() == null){
            userHandle = Base64UrlUtil.encodeToString(generateUserHandle());
        }
        else {
            userHandle = attestationOptions.getUser().getUserHandle();
        }
        ServerPublicKeyCredentialUserEntity user = new ServerPublicKeyCredentialUserEntity(userHandle, username, displayName, null);
        List<ServerPublicKeyCredentialDescriptor> credentials =
                attestationOptions.getCredentials().stream().map(ServerPublicKeyCredentialDescriptor::new).collect(Collectors.toList());
        return new ServerPublicKeyCredentialCreationOptionsResponse(
                attestationOptions.getRelyingParty(),
                user,
                Base64UrlUtil.encodeToString(attestationOptions.getChallenge().getValue()),
                attestationOptions.getPubKeyCredParams(),
                attestationOptions.getRegistrationTimeout(),
                credentials,
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
