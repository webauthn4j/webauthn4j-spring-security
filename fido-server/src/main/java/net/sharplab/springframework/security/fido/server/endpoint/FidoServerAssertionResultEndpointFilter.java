/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.fido.server.endpoint;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.fido.server.validator.ServerPublicKeyCredentialValidator;
import net.sharplab.springframework.security.webauthn.WebAuthnAssertionAuthenticationToken;
import net.sharplab.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

public class FidoServerAssertionResultEndpointFilter extends AbstractAuthenticationProcessingFilter {

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/assertion/result";

    private JsonConverter jsonConverter;
    private ServerPropertyProvider serverPropertyProvider;
    private ServerPublicKeyCredentialValidator<ServerAuthenticatorAssertionResponse> serverPublicKeyCredentialValidator;
    private TypeReference<ServerPublicKeyCredential<ServerAuthenticatorAssertionResponse>> credentialTypeRef
             = new TypeReference<ServerPublicKeyCredential<ServerAuthenticatorAssertionResponse>>() {};

    public FidoServerAssertionResultEndpointFilter(
            JsonConverter jsonConverter,
            ServerPropertyProvider serverPropertyProvider,
            RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);

        this.jsonConverter = jsonConverter;
        this.serverPropertyProvider = serverPropertyProvider;
        this.serverPublicKeyCredentialValidator = new ServerPublicKeyCredentialValidator<>();

        this.setAuthenticationSuccessHandler(new FidoServerAssertionResultEndpointSuccessHandler(jsonConverter));
        this.setAuthenticationFailureHandler(new FidoServerAssertionResultEndpointFailureHandler(jsonConverter));
        checkConfig();
    }

    public FidoServerAssertionResultEndpointFilter(JsonConverter jsonConverter, ServerPropertyProvider serverPropertyProvider, String defaultFilterProcessesUrl) {
        this(jsonConverter, serverPropertyProvider, new AntPathRequestMatcher(defaultFilterProcessesUrl, HttpMethod.POST.name()));
    }

    public FidoServerAssertionResultEndpointFilter(JsonConverter jsonConverter, ServerPropertyProvider serverPropertyProvider) {
        this(jsonConverter, serverPropertyProvider, new AntPathRequestMatcher(FILTER_URL, HttpMethod.POST.name()));
    }

    @Override
    public void afterPropertiesSet(){
        super.afterPropertiesSet();
        checkConfig();
    }

    @SuppressWarnings("squid:S2177")
    private void checkConfig(){
        Assert.notNull(serverPropertyProvider, "serverPropertyProvider must not be null");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        InputStream inputStream;
        try {
            inputStream = request.getInputStream();
        }
        catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        ServerPublicKeyCredential<ServerAuthenticatorAssertionResponse> credential =
                jsonConverter.readValue(inputStream, credentialTypeRef);
        serverPublicKeyCredentialValidator.validate(credential);

        ServerAuthenticatorAssertionResponse assertionResponse = credential.getResponse();

        ServerProperty serverProperty = serverPropertyProvider.provide(request);

        WebAuthnAuthenticationRequest webAuthnAuthenticationRequest = new WebAuthnAuthenticationRequest(
                Base64UrlUtil.decode(credential.getRawId()),
                Base64UrlUtil.decode(assertionResponse.getClientDataJSON()),
                Base64UrlUtil.decode(assertionResponse.getAuthenticatorData()),
                Base64UrlUtil.decode(assertionResponse.getSignature()),
                credential.getClientExtensionResults(),
                serverProperty,
                false,
                false
        );

        WebAuthnAssertionAuthenticationToken authRequest = new WebAuthnAssertionAuthenticationToken(webAuthnAuthenticationRequest);
        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    protected void setDetails(HttpServletRequest request, WebAuthnAssertionAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }

}
