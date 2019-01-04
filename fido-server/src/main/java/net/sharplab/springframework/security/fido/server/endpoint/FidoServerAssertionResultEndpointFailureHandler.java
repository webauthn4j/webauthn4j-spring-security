package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.registry.Registry;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class FidoServerAssertionResultEndpointFailureHandler implements AuthenticationFailureHandler {

    private ServerEndpointFilterUtil serverEndpointFilterUtil;

    public FidoServerAssertionResultEndpointFailureHandler(Registry registry) {
        this.serverEndpointFilterUtil = new ServerEndpointFilterUtil(registry);
    }

    public FidoServerAssertionResultEndpointFailureHandler(){
        this(new Registry());
    }

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse,
            AuthenticationException e) throws IOException {

        serverEndpointFilterUtil.writeErrorResponse(httpServletResponse, e);
    }
}
