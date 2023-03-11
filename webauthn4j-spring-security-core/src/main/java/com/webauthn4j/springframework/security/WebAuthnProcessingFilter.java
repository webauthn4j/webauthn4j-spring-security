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

package com.webauthn4j.springframework.security;

import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;


/**
 * Processes a WebAuthn authentication form submission.
 * <p>
 * For supporting the username/password authentication in the first step of a two factors authentication,
 * if credentialId is not found in the HTTP request, this filter try to find username/password parameters.
 * <p>
 * Login forms must present WebAuthn parameters (credentialId, clientDataJSON, authenticatorData,signature and
 * clientExtensionJSON) or Password authentication parameters (username and password).
 * The default parameter names to use are contained in the static fields
 * {@link #SPRING_SECURITY_FORM_CREDENTIAL_ID_KEY},
 * {@link #SPRING_SECURITY_FORM_CLIENT_DATA_JSON_KEY},
 * {@link #SPRING_SECURITY_FORM_AUTHENTICATOR_DATA_KEY},
 * {@link #SPRING_SECURITY_FORM_SIGNATURE_KEY}, and
 * {@link #SPRING_SECURITY_FORM_CLIENT_EXTENSIONS_JSON_KEY}.
 * The parameter names can also be changed by setting the corresponding properties.
 * <p>
 * This filter by default responds to the URL {@code /login}.
 *
 * @see WebAuthnAuthenticationProvider
 */
public class WebAuthnProcessingFilter extends UsernamePasswordAuthenticationFilter {

    // ~ Static fields/initializers
    // =====================================================================================
    public static final String SPRING_SECURITY_FORM_CREDENTIAL_ID_KEY = "credentialId";
    public static final String SPRING_SECURITY_FORM_CLIENT_DATA_JSON_KEY = "clientDataJSON";
    public static final String SPRING_SECURITY_FORM_AUTHENTICATOR_DATA_KEY = "authenticatorData";
    public static final String SPRING_SECURITY_FORM_SIGNATURE_KEY = "signature";
    public static final String SPRING_SECURITY_FORM_CLIENT_EXTENSIONS_JSON_KEY = "clientExtensionsJSON";

    //~ Instance fields
    // ================================================================================================
    private final List<GrantedAuthority> authorities;

    private String credentialIdParameter = SPRING_SECURITY_FORM_CREDENTIAL_ID_KEY;
    private String clientDataJSONParameter = SPRING_SECURITY_FORM_CLIENT_DATA_JSON_KEY;
    private String authenticatorDataParameter = SPRING_SECURITY_FORM_AUTHENTICATOR_DATA_KEY;
    private String signatureParameter = SPRING_SECURITY_FORM_SIGNATURE_KEY;
    private String clientExtensionsJSONParameter = SPRING_SECURITY_FORM_CLIENT_EXTENSIONS_JSON_KEY;

    private ServerPropertyProvider serverPropertyProvider;
    private UserVerificationStrategy userVerificationStrategy;

    private boolean postOnly = true;

    // ~ Constructors
    // ===================================================================================================

    /**
     * Constructor
     */
    public WebAuthnProcessingFilter() {
        this.authorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");
        this.serverPropertyProvider = null;
    }

    /**
     * Constructor which initializes the filter with a default user verification strategy
     *
     * @param authorities            authorities for FirstOfMultiFactorAuthenticationToken
     * @param serverPropertyProvider provider for ServerProperty
     */
    public WebAuthnProcessingFilter(List<GrantedAuthority> authorities, ServerPropertyProvider serverPropertyProvider) {
        Assert.notNull(authorities, "authorities must not be null");
        Assert.notNull(serverPropertyProvider, "serverPropertyProvider must not be null");
        this.authorities = authorities;
        this.serverPropertyProvider = serverPropertyProvider;
        this.userVerificationStrategy = new DefaultUserVerificationStrategy();
    }

    /**
     * Overloading constructor in which the user verification strategy with which initializing the filter can be specified
     *
     * @param authorities              authorities for FirstOfMultiFactorAuthenticationToken
     * @param serverPropertyProvider   provider for ServerProperty
     * @param userVerificationStrategy the user verification strategy to be used by the filter
     */
    public WebAuthnProcessingFilter(List<GrantedAuthority> authorities, ServerPropertyProvider serverPropertyProvider, UserVerificationStrategy userVerificationStrategy) {
        Assert.notNull(authorities, "authorities must not be null");
        Assert.notNull(serverPropertyProvider, "serverPropertyProvider must not be null");
        Assert.notNull(userVerificationStrategy, "userVerificationStrategy must not be null");
        this.authorities = authorities;
        this.serverPropertyProvider = serverPropertyProvider;
        this.userVerificationStrategy = userVerificationStrategy;
    }

    // ~ Methods
    // ========================================================================================================

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        if (postOnly && !HttpMethod.POST.matches(request.getMethod())) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }

        String credentialId = obtainCredentialId(request);

        if(!StringUtils.hasText(credentialId)){
            String username = obtainUsername(request);
            String password = obtainPassword(request);

            if (username == null) {
                username = "";
            }

            if (password == null) {
                password = "";
            }

            username = username.trim();

            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                    username, password);

            // Allow subclasses to set the "details" property
            setDetails(request, authRequest);

            return this.getAuthenticationManager().authenticate(authRequest);
        }
        else {
            String clientDataJSON = obtainClientDataJSON(request);
            String authenticatorData = obtainAuthenticatorData(request);
            String signature = obtainSignatureData(request);
            String clientExtensionsJSON = obtainClientExtensionsJSON(request);

            byte[] rawId = Base64UrlUtil.decode(credentialId);
            byte[] rawClientData = Base64UrlUtil.decode(clientDataJSON);
            byte[] rawAuthenticatorData = Base64UrlUtil.decode(authenticatorData);
            byte[] signatureBytes = Base64UrlUtil.decode(signature);

            ServerProperty serverProperty = serverPropertyProvider.provide(request);

            WebAuthnAuthenticationRequest webAuthnAuthenticationRequest = new WebAuthnAuthenticationRequest(
                    rawId,
                    rawClientData,
                    rawAuthenticatorData,
                    signatureBytes,
                    clientExtensionsJSON
            );
            WebAuthnAuthenticationParameters webAuthnAuthenticationParameters = new WebAuthnAuthenticationParameters(
                    serverProperty,
                    userVerificationStrategy.isUserVerificationRequired(),
                    true
            );
            AbstractAuthenticationToken authenticationToken = new WebAuthnAssertionAuthenticationToken(webAuthnAuthenticationRequest, webAuthnAuthenticationParameters, authorities);

            // Allow subclasses to set the "details" property
            setDetails(request, authenticationToken);

            return this.getAuthenticationManager().authenticate(authenticationToken);
        }
    }

    /**
     * Defines whether only HTTP POST requests will be allowed by this filter. If set to
     * true, and an authentication request is received which is not a POST request, an
     * exception will be raised immediately and authentication will not be attempted. The
     * <code>unsuccessfulAuthentication()</code> method will be called as if handling a failed
     * authentication.
     * <p>
     * Defaults to <code>true</code> but may be overridden by subclasses.
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
        Assert.hasText(credentialIdParameter, "credentialId parameter must not be empty or null");
        this.credentialIdParameter = credentialIdParameter;
    }

    public String getClientDataJSONParameter() {
        return clientDataJSONParameter;
    }

    public void setClientDataJSONParameter(String clientDataJSONParameter) {
        Assert.hasText(clientDataJSONParameter, "clientDataJSON parameter must not be empty or null");
        this.clientDataJSONParameter = clientDataJSONParameter;
    }

    public String getAuthenticatorDataParameter() {
        return authenticatorDataParameter;
    }

    public void setAuthenticatorDataParameter(String authenticatorDataParameter) {
        Assert.hasText(authenticatorDataParameter, "authenticatorData parameter must not be empty or null");
        this.authenticatorDataParameter = authenticatorDataParameter;
    }

    public String getSignatureParameter() {
        return signatureParameter;
    }

    public void setSignatureParameter(String signatureParameter) {
        Assert.hasText(signatureParameter, "signature parameter must not be empty or null");
        this.signatureParameter = signatureParameter;
    }

    public String getClientExtensionsJSONParameter() {
        return clientExtensionsJSONParameter;
    }

    public void setClientExtensionsJSONParameter(String clientExtensionsJSONParameter) {
        Assert.hasText(clientExtensionsJSONParameter, "clientExtensionsJSON parameter must not be empty or null");
        this.clientExtensionsJSONParameter = clientExtensionsJSONParameter;
    }

    public ServerPropertyProvider getServerPropertyProvider() {
        return serverPropertyProvider;
    }

    public void setServerPropertyProvider(ServerPropertyProvider serverPropertyProvider) {
        this.serverPropertyProvider = serverPropertyProvider;
    }

    public UserVerificationStrategy getUserVerificationStrategy() {
        return userVerificationStrategy;
    }

    public void setUserVerificationStrategy(UserVerificationStrategy userVerificationStrategy) {
        this.userVerificationStrategy = userVerificationStrategy;
    }

    protected void setDetails(HttpServletRequest request,
                              AbstractAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    private String obtainClientDataJSON(HttpServletRequest request) {
        return request.getParameter(clientDataJSONParameter);
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


}
