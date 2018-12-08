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

package net.sharplab.springframework.security.webauthn.options;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.registry.Registry;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OptionsEndpointFilter extends GenericFilterBean {

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/options";

    //~ Instance fields
    // ================================================================================================
    /**
     * Url this filter should get activated on.
     */
    private String filterProcessesUrl = FILTER_URL;
    private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private OptionsProvider optionsProvider;
    private AuthenticationTrustResolver trustResolver;
    private MFATokenEvaluator mfaTokenEvaluator;
    private ObjectMapper objectMapper;

    public OptionsEndpointFilter(OptionsProvider optionsProvider, Registry registry) {
        this.optionsProvider = optionsProvider;
        trustResolver = new AuthenticationTrustResolverImpl();
        mfaTokenEvaluator = new MFATokenEvaluatorImpl();
        objectMapper = registry.getJsonMapper();
    }


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        if (!processFilter(fi.getRequest())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Options options = createOptions(fi.getRequest());
            writeResponse(fi.getResponse(), options);
        } catch (RuntimeException e) {
            writeErrorResponse(fi.getResponse(), e);
        }

    }

    public AuthenticationTrustResolver getTrustResolver() {
        return trustResolver;
    }

    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }

    public MFATokenEvaluator getMfaTokenEvaluator() {
        return mfaTokenEvaluator;
    }

    public void setMFATokenEvaluator(MFATokenEvaluator mfaTokenEvaluator) {
        this.mfaTokenEvaluator = mfaTokenEvaluator;
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

    private Options createOptions(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username;
        if (trustResolver.isAnonymous(authentication) && !mfaTokenEvaluator.isMultiFactorAuthentication(authentication)) {
            username = null;
        }
        else {
            username = authentication.getName();
        }
        return optionsProvider.provide(request, username);
    }

    void writeResponse(HttpServletResponse response, Options options) throws IOException {
        String responseText = objectMapper.writeValueAsString(options);
        response.setContentType("application/json");
        response.getWriter().print(responseText);
    }

    void writeErrorResponse(HttpServletResponse response, RuntimeException e) throws IOException {
        Error error;
        int statusCode;
        if (e instanceof InsufficientAuthenticationException) {
            error = new Error(Error.Type.NOT_AUTHENTICATED, "Anonymous access is prohibited");
            statusCode = HttpServletResponse.SC_FORBIDDEN;
        } else {
            error = new Error(Error.Type.SERVER_ERROR, "The server encountered an internal error");
            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
        String errorResponseText = objectMapper.writeValueAsString(error);
        response.setContentType("application/json");
        response.getWriter().print(errorResponseText);
        response.setStatus(statusCode);
    }

}
