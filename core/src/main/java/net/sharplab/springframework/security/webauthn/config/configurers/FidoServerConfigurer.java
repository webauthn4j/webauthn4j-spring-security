package net.sharplab.springframework.security.webauthn.config.configurers;

import com.webauthn4j.registry.Registry;
import net.sharplab.springframework.security.webauthn.endpoint.FidoServerAttestationOptionsEndpointFilter;
import net.sharplab.springframework.security.webauthn.endpoint.OptionsProvider;
import net.sharplab.springframework.security.webauthn.endpoint.ServerEndpointFilterBase;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.session.SessionManagementFilter;

public class FidoServerConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<FidoServerConfigurer<H>, H> {


    //~ Instance fields
    // ================================================================================================
    private OptionsProvider optionsProvider;
    private Registry registry;

    private final FidoServerAttestationOptionsEndpointConfig fidoServerAttestationOptionsEndpointConfig = new FidoServerAttestationOptionsEndpointConfig();

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
    }

    public FidoServerAttestationOptionsEndpointConfig fidoServerAttestationOptionsEndpoint() {
        return this.fidoServerAttestationOptionsEndpointConfig;
    }

    public class FidoServerAttestationOptionsEndpointConfig extends AbstractServerEndpointConfig{

        protected FidoServerAttestationOptionsEndpointConfig() {
            super(FidoServerAttestationOptionsEndpointFilter.class);
        }

        @Override
        protected ServerEndpointFilterBase createInstance() {
            return new FidoServerAttestationOptionsEndpointFilter(registry, optionsProvider);
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
