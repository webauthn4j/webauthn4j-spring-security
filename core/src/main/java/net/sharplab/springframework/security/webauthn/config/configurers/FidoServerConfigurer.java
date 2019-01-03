package net.sharplab.springframework.security.webauthn.config.configurers;

import com.webauthn4j.registry.Registry;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.endpoint.*;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;

public class FidoServerConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<FidoServerConfigurer<H>, H> {


    //~ Instance fields
    // ================================================================================================
    private OptionsProvider optionsProvider;
    private Registry registry;

    private final FidoServerAttestationOptionsEndpointConfig fidoServerAttestationOptionsEndpointConfig = new FidoServerAttestationOptionsEndpointConfig();
    private final FidoServerAttestationResultEndpointConfig fidoServerAttestationResultEndpointConfig = new FidoServerAttestationResultEndpointConfig();
    private final FidoServerAssertionOptionsEndpointConfig fidoServerAssertionOptionsEndpointConfig = new FidoServerAssertionOptionsEndpointConfig();
    private final FidoServerAssertionResultEndpointConfig fidoServerAssertionResultEndpointConfig = new FidoServerAssertionResultEndpointConfig();

    public static FidoServerConfigurer<HttpSecurity> fidoServer() {
        return new FidoServerConfigurer<>();
    }

    @Override
    public void init(H http) throws Exception {
        super.init(http);
    }

    @Override
    public void configure(H http) throws Exception {
        super.configure(http);
        if(optionsProvider == null){
            optionsProvider = WebAuthnConfigurerUtil.getOptionsProvider(http);
        }
        http.setSharedObject(OptionsProvider.class, optionsProvider);
        if(registry == null){
            registry = WebAuthnConfigurerUtil.getRegistry(http);
        }
        http.setSharedObject(Registry.class, registry);

        fidoServerAttestationOptionsEndpointConfig.configure(http);
        fidoServerAttestationResultEndpointConfig.configure(http);
        fidoServerAttestationOptionsEndpointConfig.configure(http);
        fidoServerAssertionResultEndpointConfig.configure(http);
    }

    public FidoServerAttestationOptionsEndpointConfig fidoServerAttestationOptionsEndpoint() {
        return this.fidoServerAttestationOptionsEndpointConfig;
    }

    public FidoServerAttestationResultEndpointConfig fidoServerAttestationResultEndpointConfig() {
        return this.fidoServerAttestationResultEndpointConfig;
    }

    public FidoServerAssertionOptionsEndpointConfig fidoServerAssertionOptionsEndpointConfig() {
        return this.fidoServerAssertionOptionsEndpointConfig;
    }

    public FidoServerAssertionResultEndpointConfig fidoServerAssertionResultEndpoint(){
        return this.fidoServerAssertionResultEndpointConfig;
    }

    public FidoServerConfigurer<H> optionsProvider(OptionsProvider optionsProvider){
        Assert.notNull(optionsProvider, "optionsProvider must not be null");
        this.optionsProvider = optionsProvider;
        return this;
    }

    public FidoServerConfigurer<H> registry(Registry registry){
        Assert.notNull(registry, "registry must not be null");
        this.registry = registry;
        return this;
    }

    public class FidoServerAttestationOptionsEndpointConfig extends AbstractServerEndpointConfig{

        FidoServerAttestationOptionsEndpointConfig() {
            super(FidoServerAttestationOptionsEndpointFilter.class);
        }

        @Override
        protected ServerEndpointFilterBase createInstance() {
            return new FidoServerAttestationOptionsEndpointFilter(registry, optionsProvider);
        }
    }

    public class FidoServerAttestationResultEndpointConfig extends AbstractServerEndpointConfig<FidoServerAttestationResultEndpointFilter>{

        private WebAuthnUserDetailsService webAuthnUserDetailsService;
        private WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator;

        FidoServerAttestationResultEndpointConfig() {
            super(FidoServerAttestationResultEndpointFilter.class);
        }

        @Override
        void configure(H http) {
            super.configure(http);
            if(webAuthnUserDetailsService == null){
                webAuthnUserDetailsService = WebAuthnConfigurerUtil.getWebAuthnUserDetailsService(http);
            }
            http.setSharedObject(WebAuthnUserDetailsService.class, webAuthnUserDetailsService);
            if(webAuthnRegistrationRequestValidator == null){
                webAuthnRegistrationRequestValidator = WebAuthnConfigurerUtil.getWebAuthnRegistrationRequestValidator(http);
            }
            http.setSharedObject(WebAuthnRegistrationRequestValidator.class, webAuthnRegistrationRequestValidator);
        }

        public FidoServerAttestationResultEndpointConfig webAuthnUserDetailsService(WebAuthnUserDetailsService webAuthnUserDetailsService){
            Assert.notNull(webAuthnUserDetailsService, "webAuthnUserDetailsService must not be null");
            this.webAuthnUserDetailsService = webAuthnUserDetailsService;
            return this;
        }

        public FidoServerAttestationResultEndpointConfig webAuthnRegistrationRequestValidator(WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator){
            Assert.notNull(webAuthnRegistrationRequestValidator, "webAuthnRegistrationRequestValidator must not be null");
            this.webAuthnRegistrationRequestValidator = webAuthnRegistrationRequestValidator;
            return this;
        }

        @Override
        protected FidoServerAttestationResultEndpointFilter createInstance() {
            return new FidoServerAttestationResultEndpointFilter(registry, webAuthnUserDetailsService, webAuthnRegistrationRequestValidator);
        }
    }

    public class FidoServerAssertionOptionsEndpointConfig extends AbstractServerEndpointConfig<FidoServerAssertionOptionsEndpointFilter>{

        FidoServerAssertionOptionsEndpointConfig() {
            super(FidoServerAssertionOptionsEndpointFilter.class);
        }

        @Override
        protected FidoServerAssertionOptionsEndpointFilter createInstance() {
            return new FidoServerAssertionOptionsEndpointFilter(registry, optionsProvider);
        }
    }

    private class FidoServerAssertionResultEndpointConfig{

        private String filterProcessingUrl = null;
        private ServerPropertyProvider serverPropertyProvider = null;

        FidoServerAssertionResultEndpointConfig() {
        }

        void configure(H http) {
            FidoServerAssertionResultEndpointFilter serverEndpointFilter;

            if (serverPropertyProvider == null) {
                serverPropertyProvider = WebAuthnConfigurerUtil.getServerPropertyProvider(http);
            }
            http.setSharedObject(ServerPropertyProvider.class, serverPropertyProvider);

            ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
            String[] beanNames = applicationContext.getBeanNamesForType(FidoServerAssertionResultEndpointFilter.class);
            if (beanNames.length == 0) {
                serverEndpointFilter = new FidoServerAssertionResultEndpointFilter(registry, serverPropertyProvider);
                if(filterProcessingUrl != null){
                    serverEndpointFilter.setFilterProcessesUrl(filterProcessingUrl);
                }
            }
            else {
                serverEndpointFilter = applicationContext.getBean(FidoServerAssertionResultEndpointFilter.class);
            }
            http.setSharedObject(FidoServerAssertionResultEndpointFilter.class, serverEndpointFilter);
            http.addFilterAfter(serverEndpointFilter, UsernamePasswordAuthenticationFilter.class);
        }


        public FidoServerConfigurer<H>.FidoServerAssertionResultEndpointConfig serverPropertyProvider(ServerPropertyProvider serverPropertyProvider) {
            this.serverPropertyProvider = serverPropertyProvider;
            return this;
        }

        public FidoServerConfigurer<H>.FidoServerAssertionResultEndpointConfig processingUrl(String processingUrl) {
            this.filterProcessingUrl = processingUrl;
            return this;
        }

        public FidoServerConfigurer<H> and() {
            return FidoServerConfigurer.this;
        }

    }

    public abstract class AbstractServerEndpointConfig<F extends ServerEndpointFilterBase>{

        private Class<F> filterClass;
        private String filterProcessingUrl = null;

        AbstractServerEndpointConfig(Class<F> filterClass){
            this.filterClass = filterClass;
        }

        void configure(H http) {
            F serverEndpointFilter;
            ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
            String[] beanNames = applicationContext.getBeanNamesForType(filterClass);
            if (beanNames.length == 0) {
                serverEndpointFilter = createInstance();
                if(filterProcessingUrl != null){
                    serverEndpointFilter.setFilterProcessesUrl(filterProcessingUrl);
                }
            }
            else {
                serverEndpointFilter = applicationContext.getBean(filterClass);
            }
            http.setSharedObject(filterClass, serverEndpointFilter);
            http.addFilterAfter(serverEndpointFilter, SessionManagementFilter.class);
        }

        public FidoServerConfigurer<H>.AbstractServerEndpointConfig<F> processingUrl(String processingUrl) {
            this.filterProcessingUrl = processingUrl;
            return this;
        }

        public FidoServerConfigurer<H> and() {
            return FidoServerConfigurer.this;
        }

        protected abstract F createInstance();
    }
}
