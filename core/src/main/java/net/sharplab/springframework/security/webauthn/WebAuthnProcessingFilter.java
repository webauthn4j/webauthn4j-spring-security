/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.server.ServerProperty;
import net.sharplab.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import net.sharplab.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.FirstOfMultiFactorAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;


/**
 * WebAuthnProcessingFilter
 */
public class WebAuthnProcessingFilter extends UsernamePasswordAuthenticationFilter {

    // ~ Static fields/initializers
    // =====================================================================================
    public static final String SPRING_SECURITY_FORM_CREDENTIAL_ID_KEY = "credentialId";
    public static final String SPRING_SECURITY_FORM_CLIENTDATA_KEY = "clientData";
    public static final String SPRING_SECURITY_FORM_AUTHENTICATOR_DATA_KEY = "authenticatorData";
    public static final String SPRING_SECURITY_FORM_SIGNATURE_KEY = "signature";
    public static final String SPRING_SECURITY_FORM_CLIENT_EXTENSIONS_JSON_PARAMETER = "clientExtensionsJSON";

    //~ Instance fields
    // ================================================================================================
    private List<GrantedAuthority> authorities;

    private String credentialIdParameter = SPRING_SECURITY_FORM_CREDENTIAL_ID_KEY;
    private String clientDataParameter = SPRING_SECURITY_FORM_CLIENTDATA_KEY;
    private String authenticatorDataParameter = SPRING_SECURITY_FORM_AUTHENTICATOR_DATA_KEY;
    private String signatureParameter = SPRING_SECURITY_FORM_SIGNATURE_KEY;
    private String clientExtensionsJSONParameter = SPRING_SECURITY_FORM_CLIENT_EXTENSIONS_JSON_PARAMETER;

    private ServerPropertyProvider serverPropertyProvider;


    private boolean postOnly = true;

    /**
     * Default constructor
     */
    public WebAuthnProcessingFilter() {
        this(AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"), new ServerPropertyProviderImpl(new HttpSessionChallengeRepository()));
    }

    /**
     * Constructor
     *
     * @param authorities            authorities for FirstOfMultiFactorAuthenticationToken
     * @param serverPropertyProvider provide for ServerProperty
     */
    public WebAuthnProcessingFilter(List<GrantedAuthority> authorities, ServerPropertyProvider serverPropertyProvider) {
        super();
        Assert.notNull(authorities, "authorities must be set");
        Assert.notNull(serverPropertyProvider, "serverPropertyProvider must be set");
        this.authorities = authorities;
        this.serverPropertyProvider = serverPropertyProvider;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        if (postOnly && !HttpMethod.POST.matches(request.getMethod())) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        String credentialId = obtainCredentialId(request);
        String clientData = obtainClientData(request);
        String authenticatorData = obtainAuthenticatorData(request);
        String signature = obtainSignatureData(request);
        String clientExtensionsJSON = obtainClientExtensionsJSON(request);

        AbstractAuthenticationToken authRequest;
        if (StringUtils.isEmpty(credentialId)) {
            authRequest = new FirstOfMultiFactorAuthenticationToken(username, password, authorities);
        } else {
            byte[] rawId = Base64Utils.decodeFromUrlSafeString(credentialId);
            byte[] rawClientData = Base64Utils.decodeFromUrlSafeString(clientData);
            byte[] rawAuthenticatorData = Base64Utils.decodeFromUrlSafeString(authenticatorData);
            byte[] signatureBytes = Base64Utils.decodeFromUrlSafeString(signature);

            ServerProperty serverProperty = serverPropertyProvider.provide(request);

            WebAuthnAuthenticationRequest webAuthnAuthenticationRequest = new WebAuthnAuthenticationRequest(
                    rawId,
                    rawClientData,
                    rawAuthenticatorData,
                    signatureBytes,
                    clientExtensionsJSON,
                    serverProperty
            );
            authRequest = new WebAuthnAssertionAuthenticationToken(webAuthnAuthenticationRequest);
        }

        // Allow subclasses to set the "details" property
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
    @Override
    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public String getCredentialIdParameter() {
        return credentialIdParameter;
    }

    public void setCredentialIdParameter(String credentialIdParameter) {
        this.credentialIdParameter = credentialIdParameter;
    }

    public String getClientDataParameter() {
        return clientDataParameter;
    }

    public void setClientDataParameter(String clientDataParameter) {
        this.clientDataParameter = clientDataParameter;
    }

    public String getAuthenticatorDataParameter() {
        return authenticatorDataParameter;
    }

    public void setAuthenticatorDataParameter(String authenticatorDataParameter) {
        this.authenticatorDataParameter = authenticatorDataParameter;
    }

    public String getSignatureParameter() {
        return signatureParameter;
    }

    public void setSignatureParameter(String signatureParameter) {
        this.signatureParameter = signatureParameter;
    }

    public String getClientExtensionsJSONParameter() {
        return clientExtensionsJSONParameter;
    }

    public void setClientExtensionsJSONParameter(String clientExtensionsJSONParameter) {
        this.clientExtensionsJSONParameter = clientExtensionsJSONParameter;
    }

    public ServerPropertyProvider getServerPropertyProvider() {
        return serverPropertyProvider;
    }

    public void setServerPropertyProvider(ServerPropertyProvider serverPropertyProvider) {
        this.serverPropertyProvider = serverPropertyProvider;
    }


    private String obtainClientData(HttpServletRequest request) {
        return request.getParameter(clientDataParameter);
    }

    private String obtainCredentialId(HttpServletRequest request) {
        return request.getParameter(credentialIdParameter);
    }

    private String obtainAuthenticatorData(HttpServletRequest request) {
        return request.getParameter(authenticatorDataParameter);
    }

    private String obtainSignatureData(HttpServletRequest request) {
        return request.getParameter(signatureParameter);
    }

    private String obtainClientExtensionsJSON(HttpServletRequest request) {
        return request.getParameter(clientExtensionsJSONParameter);
    }

    private void setDetails(HttpServletRequest request,
                            AbstractAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }
}
