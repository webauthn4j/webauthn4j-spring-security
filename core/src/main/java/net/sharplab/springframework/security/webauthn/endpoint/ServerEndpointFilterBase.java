package net.sharplab.springframework.security.webauthn.endpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.*;
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

public abstract class ServerEndpointFilterBase extends GenericFilterBean {

    //~ Instance fields
    // ================================================================================================
    /**
     * Url this filter should get activated on.
     */
    protected String filterProcessesUrl;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private AuthenticationTrustResolver trustResolver;
    private MFATokenEvaluator mfaTokenEvaluator;

    protected ObjectMapper objectMapper;

    public ServerEndpointFilterBase(
            String filterProcessesUrl,
            ObjectMapper objectMapper) {
        this.filterProcessesUrl = filterProcessesUrl;
        this.objectMapper = objectMapper;
        this.trustResolver = new AuthenticationTrustResolverImpl();
        this.mfaTokenEvaluator = new MFATokenEvaluatorImpl();
        checkConfig();
    }

    public ServerEndpointFilterBase(){}

    @Override
    public void afterPropertiesSet() {
        checkConfig();
    }

    private void checkConfig() {
        Assert.notNull(filterProcessesUrl, "filterProcessesUrl must not be null");
        Assert.notNull(objectMapper, "objectMapper must not be null");
        Assert.notNull(trustResolver, "trustResolver must not be null");
        Assert.notNull(mfaTokenEvaluator, "mfaTokenEvaluator must not be null");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        if (!processFilter(fi.getRequest())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            ServerResponse serverResponse = processRequest(fi.getRequest());
            writeResponse(fi.getResponse(), serverResponse);
        } catch (RuntimeException e) {
            writeErrorResponse(fi.getResponse(), e);
        }

    }

    protected abstract ServerResponse processRequest(HttpServletRequest request);

    void writeResponse(HttpServletResponse httpServletResponse, ServerResponse response) throws IOException {
        String responseText = objectMapper.writeValueAsString(response);
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().print(responseText);
    }

    void writeErrorResponse(HttpServletResponse httpServletResponse, RuntimeException e) throws IOException {
        ErrorResponse errorResponse;
        int statusCode;
        if (e instanceof InsufficientAuthenticationException) {
            errorResponse = new ErrorResponse("Anonymous access is prohibited");
            statusCode = HttpServletResponse.SC_FORBIDDEN;
        } else {
            errorResponse = new ErrorResponse("The server encountered an internal error");
            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
        String errorResponseText = objectMapper.writeValueAsString(errorResponse);
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().print(errorResponseText);
        httpServletResponse.setStatus(statusCode);
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


    protected String getLoginUsername(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (trustResolver.isAnonymous(authentication) && !mfaTokenEvaluator.isMultiFactorAuthentication(authentication)) {
            return null;
        }
        else {
            return authentication.getName();
        }
    }

    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    public void setFilterProcessesUrl(String filterProcessesUrl) {
        Assert.hasText(filterProcessesUrl, "filterProcessesUrl parameter must not be empty or null");
        this.filterProcessesUrl = filterProcessesUrl;
    }

    public ObjectMapper getObjectMapper() {
        return objectMapper;
    }

    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public AuthenticationTrustResolver getTrustResolver() {
        return trustResolver;
    }

    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }

    public MFATokenEvaluator getMFATokenEvaluator() {
        return mfaTokenEvaluator;
    }

    public void setMFATokenEvaluator(MFATokenEvaluator mfaTokenEvaluator) {
        this.mfaTokenEvaluator = mfaTokenEvaluator;
    }
}
