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

import com.webauthn4j.converter.util.JsonConverter;
import net.sharplab.springframework.security.webauthn.util.ExceptionUtil;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.SpringSecurityMessageSource;
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

public abstract class ServerEndpointFilterBase extends GenericFilterBean {

    //~ Instance fields
    // ================================================================================================
    /**
     * Url this filter should get activated on.
     */
    private String filterProcessesUrl;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    protected JsonConverter jsonConverter;
    protected ServerEndpointFilterUtil serverEndpointFilterUtil;


    public ServerEndpointFilterBase(
            String filterProcessesUrl,
            JsonConverter jsonConverter) {
        this.filterProcessesUrl = filterProcessesUrl;
        this.jsonConverter = jsonConverter;
        this.serverEndpointFilterUtil = new ServerEndpointFilterUtil(this.jsonConverter);
        checkConfig();
    }

    public ServerEndpointFilterBase() {
    }

    @Override
    public void afterPropertiesSet() {
        checkConfig();
    }

    private void checkConfig() {
        Assert.notNull(filterProcessesUrl, "filterProcessesUrl must not be null");
        Assert.notNull(jsonConverter, "jsonConverter must not be null");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        try {
            HttpServletRequest httpServletRequest = fi.getRequest();
            HttpServletResponse httpServletResponse = fi.getResponse();
            if (!httpServletRequest.getMethod().equals(HttpMethod.POST.name())) {
                throw new AuthenticationServiceException("Authentication method not supported: " + httpServletRequest.getMethod());
            }

            if (!processFilter(httpServletRequest)) {
                chain.doFilter(request, response);
                return;
            }

            try{
                ServerResponse serverResponse = processRequest(httpServletRequest);
                serverEndpointFilterUtil.writeResponse(httpServletResponse, serverResponse);
            }
            catch (RuntimeException e){
                throw ExceptionUtil.wrapWithAuthenticationException(e);
            }
        }
        catch (RuntimeException e) {
            logger.debug("RuntimeException is thrown", e);
            serverEndpointFilterUtil.writeErrorResponse(fi.getResponse(), e);
        }
    }

    protected abstract ServerResponse processRequest(HttpServletRequest request);

    /**
     * The filter will be used in case the URL of the request contains the FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    private boolean processFilter(HttpServletRequest request) {
        return (request.getRequestURI().contains(filterProcessesUrl));
    }

    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    public void setFilterProcessesUrl(String filterProcessesUrl) {
        Assert.hasText(filterProcessesUrl, "filterProcessesUrl parameter must not be empty or null");
        this.filterProcessesUrl = filterProcessesUrl;
    }

}
