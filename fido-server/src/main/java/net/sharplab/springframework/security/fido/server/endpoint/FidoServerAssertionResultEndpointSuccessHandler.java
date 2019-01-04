package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.registry.Registry;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class FidoServerAssertionResultEndpointSuccessHandler implements AuthenticationSuccessHandler {

    private ServerEndpointFilterUtil serverEndpointFilterUtil;

    public FidoServerAssertionResultEndpointSuccessHandler(Registry registry) {
        this.serverEndpointFilterUtil = new ServerEndpointFilterUtil(registry);
    }

    public FidoServerAssertionResultEndpointSuccessHandler(){
        this(new Registry());
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse,
            Authentication authentication) throws IOException {

        AssertionResultSuccessResponse successResponse = new AssertionResultSuccessResponse();
        serverEndpointFilterUtil.writeResponse(httpServletResponse, successResponse);

    }
}
