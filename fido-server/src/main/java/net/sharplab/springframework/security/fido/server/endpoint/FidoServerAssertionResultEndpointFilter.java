package net.sharplab.springframework.security.fido.server.endpoint;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.webauthn.WebAuthnAssertionAuthenticationToken;
import net.sharplab.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.fido.server.util.BeanAssertUtil;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UncheckedIOException;

public class FidoServerAssertionResultEndpointFilter extends AbstractAuthenticationProcessingFilter {

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/assertion/result";

    private ObjectMapper jsonMapper;
    private ServerPropertyProvider serverPropertyProvider;

    private boolean postOnly = true;

    public FidoServerAssertionResultEndpointFilter(
            Registry registry,
            ServerPropertyProvider serverPropertyProvider,
            RequestMatcher requiresAuthenticationRequestMatcher){
        super(requiresAuthenticationRequestMatcher);

        this.jsonMapper = registry.getJsonMapper();
        this.serverPropertyProvider = serverPropertyProvider;

        this.setAuthenticationSuccessHandler(new FidoServerAssertionResultEndpointSuccessHandler(registry));
        this.setAuthenticationFailureHandler(new FidoServerAssertionResultEndpointFailureHandler(registry));
    }

    public FidoServerAssertionResultEndpointFilter(Registry registry, ServerPropertyProvider serverPropertyProvider, String defaultFilterProcessesUrl) {
        this(registry, serverPropertyProvider, new AntPathRequestMatcher(defaultFilterProcessesUrl, HttpMethod.POST.name()));
    }

    public FidoServerAssertionResultEndpointFilter(Registry registry, ServerPropertyProvider serverPropertyProvider) {
        this(registry, serverPropertyProvider, new AntPathRequestMatcher(FILTER_URL, HttpMethod.POST.name()));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        if (this.postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        ServerPublicKeyCredential<ServerAuthenticatorAssertionResponse> credential;
        try {
            credential = jsonMapper.readValue(request.getInputStream(),
                    new TypeReference<ServerPublicKeyCredential<ServerAuthenticatorAssertionResponse>>(){});
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        BeanAssertUtil.validate(credential);

        ServerAuthenticatorAssertionResponse assertionResponse = credential.getResponse();

        ServerProperty serverProperty = serverPropertyProvider.provide(request);

        WebAuthnAuthenticationRequest webAuthnAuthenticationRequest = new WebAuthnAuthenticationRequest(
                Base64UrlUtil.decode(credential.getRawId()),
                Base64UrlUtil.decode(assertionResponse.getClientDataJSON()),
                Base64UrlUtil.decode(assertionResponse.getAuthenticatorData()),
                Base64UrlUtil.decode(assertionResponse.getSignature()),
                credential.getClientExtensionResults(),
                serverProperty
        );

        WebAuthnAssertionAuthenticationToken authRequest = new WebAuthnAssertionAuthenticationToken(webAuthnAuthenticationRequest);
        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * Defines whether only HTTP POST requests will be allowed by this filter. If set to
     * true, and an authentication request is received which is not a POST request, an
     * exception will be raised immediately and authentication will not be attempted. The
     * <tt>unsuccessfulAuthentication()</tt> method will be called as if handling a failed
     * authentication.
     * <p>
     * Defaults to <tt>true</tt> but may be overridden by subclasses.
     *
     * @param postOnly Flag to restrict HTTP method to POST.
     */
    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    protected void setDetails(HttpServletRequest request, WebAuthnAssertionAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }


}
