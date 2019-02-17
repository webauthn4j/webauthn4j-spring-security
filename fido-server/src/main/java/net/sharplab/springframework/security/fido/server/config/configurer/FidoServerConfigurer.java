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

package net.sharplab.springframework.security.fido.server.config.configurer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.util.JsonConverter;
import net.sharplab.springframework.security.fido.server.endpoint.*;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.config.configurers.WebAuthnConfigurerUtil;
import net.sharplab.springframework.security.webauthn.options.OptionsProvider;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;

public class FidoServerConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<FidoServerConfigurer<H>, H> {


    private final FidoServerAttestationOptionsEndpointConfig fidoServerAttestationOptionsEndpointConfig = new FidoServerAttestationOptionsEndpointConfig();
    private final FidoServerAttestationResultEndpointConfig fidoServerAttestationResultEndpointConfig = new FidoServerAttestationResultEndpointConfig();
    private final FidoServerAssertionOptionsEndpointConfig fidoServerAssertionOptionsEndpointConfig = new FidoServerAssertionOptionsEndpointConfig();
    private final FidoServerAssertionResultEndpointConfig fidoServerAssertionResultEndpointConfig = new FidoServerAssertionResultEndpointConfig();
    //~ Instance fields
    // ================================================================================================
    private OptionsProvider optionsProvider;
    private JsonConverter jsonConverter;

    public static FidoServerConfigurer<HttpSecurity> fidoServer() {
        return new FidoServerConfigurer<>();
    }

    @Override
    public void configure(H http) throws Exception {
        super.configure(http);
        if (optionsProvider == null) {
            optionsProvider = WebAuthnConfigurerUtil.getOptionsProvider(http);
        }
        http.setSharedObject(OptionsProvider.class, optionsProvider);
        if (jsonConverter == null) {
            jsonConverter = WebAuthnConfigurerUtil.getJsonConverter(http);
        }
        http.setSharedObject(JsonConverter.class, jsonConverter);

        fidoServerAttestationOptionsEndpointConfig.configure(http);
        fidoServerAttestationResultEndpointConfig.configure(http);
        fidoServerAssertionOptionsEndpointConfig.configure(http);
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

    public FidoServerAssertionResultEndpointConfig fidoServerAssertionResultEndpoint() {
        return this.fidoServerAssertionResultEndpointConfig;
    }

    public FidoServerConfigurer<H> optionsProvider(OptionsProvider optionsProvider) {
        Assert.notNull(optionsProvider, "optionsProvider must not be null");
        this.optionsProvider = optionsProvider;
        return this;
    }

    public FidoServerConfigurer<H> jsonConverter(JsonConverter jsonConverter) {
        Assert.notNull(jsonConverter, "jsonConverter must not be null");
        this.jsonConverter = jsonConverter;
        return this;
    }

    public class FidoServerAttestationOptionsEndpointConfig extends AbstractServerEndpointConfig<FidoServerAttestationOptionsEndpointFilter> {

        FidoServerAttestationOptionsEndpointConfig() {
            super(FidoServerAttestationOptionsEndpointFilter.class);
        }

        @Override
        protected FidoServerAttestationOptionsEndpointFilter createInstance() {
            return new FidoServerAttestationOptionsEndpointFilter(jsonConverter, optionsProvider);
        }
    }

    public class FidoServerAttestationResultEndpointConfig extends AbstractServerEndpointConfig<FidoServerAttestationResultEndpointFilter> {

        private WebAuthnUserDetailsService webAuthnUserDetailsService;
        private WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator;
        private UsernameNotFoundHandler usernameNotFoundHandler;

        FidoServerAttestationResultEndpointConfig() {
            super(FidoServerAttestationResultEndpointFilter.class);
        }

        @Override
        void configure(H http) {
            super.configure(http);
            if (webAuthnUserDetailsService == null) {
                webAuthnUserDetailsService = WebAuthnConfigurerUtil.getWebAuthnUserDetailsService(http);
            }
            http.setSharedObject(WebAuthnUserDetailsService.class, webAuthnUserDetailsService);
            if (webAuthnRegistrationRequestValidator == null) {
                webAuthnRegistrationRequestValidator = WebAuthnConfigurerUtil.getWebAuthnRegistrationRequestValidator(http);
            }
            http.setSharedObject(WebAuthnRegistrationRequestValidator.class, webAuthnRegistrationRequestValidator);
        }

        public FidoServerAttestationResultEndpointConfig webAuthnUserDetailsService(WebAuthnUserDetailsService webAuthnUserDetailsService) {
            Assert.notNull(webAuthnUserDetailsService, "webAuthnUserDetailsService must not be null");
            this.webAuthnUserDetailsService = webAuthnUserDetailsService;
            return this;
        }

        public FidoServerAttestationResultEndpointConfig webAuthnRegistrationRequestValidator(WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator) {
            Assert.notNull(webAuthnRegistrationRequestValidator, "webAuthnRegistrationRequestValidator must not be null");
            this.webAuthnRegistrationRequestValidator = webAuthnRegistrationRequestValidator;
            return this;
        }

        public FidoServerAttestationResultEndpointConfig usernameNotFoundHandler(UsernameNotFoundHandler usernameNotFoundHandler) {
            Assert.notNull(usernameNotFoundHandler, "usernameNotFoundHandler must not be null");
            this.usernameNotFoundHandler = usernameNotFoundHandler;
            return this;
        }

        @Override
        protected FidoServerAttestationResultEndpointFilter createInstance() {
            FidoServerAttestationResultEndpointFilter filter = new FidoServerAttestationResultEndpointFilter(jsonConverter, webAuthnUserDetailsService, webAuthnRegistrationRequestValidator);
            filter.setUsernameNotFoundHandler(usernameNotFoundHandler);
            return filter;
        }
    }

    public class FidoServerAssertionOptionsEndpointConfig extends AbstractServerEndpointConfig<FidoServerAssertionOptionsEndpointFilter> {

        FidoServerAssertionOptionsEndpointConfig() {
            super(FidoServerAssertionOptionsEndpointFilter.class);
        }

        @Override
        protected FidoServerAssertionOptionsEndpointFilter createInstance() {
            return new FidoServerAssertionOptionsEndpointFilter(jsonConverter, optionsProvider);
        }
    }

    private class FidoServerAssertionResultEndpointConfig {

        private String filterProcessingUrl = null;
        private AuthenticationManager authenticationManager;
        private ServerPropertyProvider serverPropertyProvider = null;

        FidoServerAssertionResultEndpointConfig() {
        }

        void configure(H http) {

            if (authenticationManager == null) {
                authenticationManager = http.getSharedObject(AuthenticationManager.class);
            }
            http.setSharedObject(AuthenticationManager.class, authenticationManager);

            FidoServerAssertionResultEndpointFilter serverEndpointFilter;

            if (serverPropertyProvider == null) {
                serverPropertyProvider = WebAuthnConfigurerUtil.getServerPropertyProvider(http);
            }
            http.setSharedObject(ServerPropertyProvider.class, serverPropertyProvider);

            ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
            String[] beanNames = applicationContext.getBeanNamesForType(FidoServerAssertionResultEndpointFilter.class);
            if (beanNames.length == 0) {
                serverEndpointFilter = new FidoServerAssertionResultEndpointFilter(jsonConverter, serverPropertyProvider);
                if (filterProcessingUrl != null) {
                    serverEndpointFilter.setFilterProcessesUrl(filterProcessingUrl);
                }
            } else {
                serverEndpointFilter = applicationContext.getBean(FidoServerAssertionResultEndpointFilter.class);
            }
            serverEndpointFilter.setAuthenticationManager(authenticationManager);
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

    public abstract class AbstractServerEndpointConfig<F extends ServerEndpointFilterBase> {

        private Class<F> filterClass;
        private String filterProcessingUrl = null;

        AbstractServerEndpointConfig(Class<F> filterClass) {
            this.filterClass = filterClass;
        }

        void configure(H http) {
            F serverEndpointFilter;
            ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
            String[] beanNames = applicationContext.getBeanNamesForType(filterClass);
            if (beanNames.length == 0) {
                serverEndpointFilter = createInstance();
                if (filterProcessingUrl != null) {
                    serverEndpointFilter.setFilterProcessesUrl(filterProcessingUrl);
                }
            } else {
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
