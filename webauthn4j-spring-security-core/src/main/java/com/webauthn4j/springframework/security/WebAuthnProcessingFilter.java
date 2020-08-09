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
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;


/**
 * Processes a WebAuthn authentication form submission. For supporting username/password authentication for first step of
 * two step authentication, if credentialId is not found in the HTTP request, this filter try to find username/password
 * parameters.
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
    private UserVerificationStrategy userVerificationStrategy = new DefaultUserVerificationStrategy();
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

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
     * Constructor
     *
     * @param authorities            authorities for FirstOfMultiFactorAuthenticationToken
     * @param serverPropertyProvider provider for ServerProperty
     */
    public WebAuthnProcessingFilter(List<GrantedAuthority> authorities, ServerPropertyProvider serverPropertyProvider) {
        Assert.notNull(authorities, "authorities must not be null");
        Assert.notNull(serverPropertyProvider, "serverPropertyProvider must not be null");
        this.authorities = authorities;
        this.serverPropertyProvider = serverPropertyProvider;
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

        if(StringUtils.isEmpty(credentialId)){
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

            byte[] rawId = Base64Utils.decodeFromUrlSafeString(credentialId);
            byte[] rawClientData = Base64Utils.decodeFromUrlSafeString(clientDataJSON);
            byte[] rawAuthenticatorData = Base64Utils.decodeFromUrlSafeString(authenticatorData);
            byte[] signatureBytes = Base64Utils.decodeFromUrlSafeString(signature);

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
        this.credentialIdParameter = credentialIdParameter;
    }

    public String getClientDataJSONParameter() {
        return clientDataJSONParameter;
    }

    public void setClientDataJSONParameter(String clientDataJSONParameter) {
        this.clientDataJSONParameter = clientDataJSONParameter;
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

    private class DefaultUserVerificationStrategy implements UserVerificationStrategy {

        @Override
        public boolean isUserVerificationRequired() {
            Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
            if(currentAuthentication == null){
                return true;
            }
            if(trustResolver.isAnonymous(currentAuthentication)){
                return true;
            }
            return !currentAuthentication.isAuthenticated();
        }
    }
}
