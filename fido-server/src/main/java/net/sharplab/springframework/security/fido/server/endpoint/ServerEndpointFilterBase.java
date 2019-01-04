package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.registry.Registry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public abstract class ServerEndpointFilterBase extends GenericFilterBean {

    //~ Instance fields
    // ================================================================================================
    private Logger logger = LoggerFactory.getLogger(ServerEndpointFilterBase.class);
    /**
     * Url this filter should get activated on.
     */
    protected String filterProcessesUrl;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    protected Registry registry;
    protected ServerEndpointFilterUtil serverEndpointFilterUtil;


    public ServerEndpointFilterBase(
            String filterProcessesUrl,
            Registry registry) {
        this.filterProcessesUrl = filterProcessesUrl;
        this.registry = registry;
        this.serverEndpointFilterUtil = new ServerEndpointFilterUtil(registry);
        checkConfig();
    }

    public ServerEndpointFilterBase(){}

    @Override
    public void afterPropertiesSet() {
        checkConfig();
    }

    private void checkConfig() {
        Assert.notNull(filterProcessesUrl, "filterProcessesUrl must not be null");
        Assert.notNull(registry, "registry must not be null");
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
            serverEndpointFilterUtil.writeResponse(fi.getResponse(), serverResponse);
        } catch (RuntimeException e) {
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
