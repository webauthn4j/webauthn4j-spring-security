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

package com.webauthn4j.springframework.security.endpoint;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.springframework.security.options.AttestationOptions;
import com.webauthn4j.springframework.security.options.OptionsProvider;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A filter for providing WebAuthn attestation option parameters to clients.
 * Clients can retrieve {@link AttestationOptions}, which includes {@link Challenge}, {@link PublicKeyCredentialRpEntity} and etc.
 */
public class AttestationOptionsEndpointFilter extends GenericFilterBean {

    // ~ Static fields/initializers
    // =====================================================================================

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/attestation/options";

    //~ Instance fields
    // ================================================================================================

    /**
     * Url this filter should get activated on.
     */
    protected String filterProcessesUrl = FILTER_URL;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    protected final JsonConverter jsonConverter;

    private AuthenticationTrustResolver trustResolver;

    private final OptionsProvider optionsProvider;

    // ~ Constructors
    // ===================================================================================================

    public AttestationOptionsEndpointFilter(OptionsProvider optionsProvider, ObjectConverter objectConverter) {
        this.optionsProvider = optionsProvider;
        this.jsonConverter = objectConverter.getJsonConverter();
        this.trustResolver = new AuthenticationTrustResolverImpl();
        checkConfig();
    }

    // ~ Methods
    // ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        checkConfig();
    }

    private void checkConfig() {
        Assert.notNull(filterProcessesUrl, "filterProcessesUrl must not be null");
        Assert.notNull(jsonConverter, "jsonConverter must not be null");
        Assert.notNull(trustResolver, "trustResolver must not be null");
        Assert.notNull(optionsProvider, "optionsProvider must not be null");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        if (!processFilter(fi.getRequest())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String loginUsername = getLoginUsername();
            AttestationOptions attestationOptions = optionsProvider.getAttestationOptions(fi.getRequest(), loginUsername, null);
            writeResponse(fi.getResponse(), attestationOptions);
        } catch (RuntimeException e) {
            logger.debug(e);
            writeErrorResponse(fi.getResponse(), e);
        }

    }

    public AuthenticationTrustResolver getTrustResolver() {
        return trustResolver;
    }

    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }


    /**
     * The filter will be used in case the URL of the request contains the FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    private boolean processFilter(HttpServletRequest request) {
        return (request.getRequestURI().contains(filterProcessesUrl));
    }

    void writeResponse(HttpServletResponse httpServletResponse, AttestationOptions attestationOptions) throws IOException {
        String responseText = jsonConverter.writeValueAsString(attestationOptions);
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().print(responseText);
    }

    void writeErrorResponse(HttpServletResponse httpServletResponse, RuntimeException e) throws IOException {
        Response errorResponse;
        int statusCode;
        if (e instanceof InsufficientAuthenticationException) {
            errorResponse = new ErrorResponse("Anonymous access is prohibited");
            statusCode = HttpServletResponse.SC_FORBIDDEN;
        } else {
            errorResponse = new ErrorResponse("The server encountered an internal error");
            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
        String errorResponseText = jsonConverter.writeValueAsString(errorResponse);
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().print(errorResponseText);
        httpServletResponse.setStatus(statusCode);
    }

    String getLoginUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || trustResolver.isAnonymous(authentication)) {
            return null;
        } else {
            return authentication.getName();
        }
    }

    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.filterProcessesUrl = filterProcessesUrl;
    }

}
