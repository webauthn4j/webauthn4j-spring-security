package net.sharplab.springframework.security.webauthn.endpoint;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.registry.Registry;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UncheckedIOException;

public class FidoServerAssertionResultEndpointFilter extends ServerEndpointFilterBase{

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/assertion/result";

    public FidoServerAssertionResultEndpointFilter(Registry registry){
        super(FILTER_URL, registry.getJsonMapper());
    }

    @Override
    protected ServerResponse processRequest(HttpServletRequest request) {
        ServerPublicKeyCredential<ServerAuthenticatorAssertionResponse> credential;
        try {
            credential = objectMapper.readValue(request.getInputStream(),
                    new TypeReference<ServerPublicKeyCredential<ServerAuthenticatorAssertionResponse>>(){});
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return new AssertionResultSuccessResponse();
    }

}
