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

package com.webauthn4j.springframework.security.config.configurers;

import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.springframework.security.options.OptionsProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * An {@link AbstractHttpConfigurer} that provides support for the
 * <a target="_blank" href="https://www.w3.org/TR/webauthn/">Web Authentication</a>.
 *
 * <h2>Shared Objects Created</h2>
 * <p>
 * The following shared objects are populated
 * <ul>
 * <li>{@link OptionsProvider}</li>
 * </ul>
 *
 * @see WebAuthnAuthenticationProviderConfigurer
 */
public class WebAuthnConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<WebAuthnConfigurer<H>, H> {

    private final WebAuthnConfigurer<H>.PublicKeyCredParamsConfig publicKeyCredParamsConfig = new WebAuthnConfigurer<H>.PublicKeyCredParamsConfig();
    private final RegistrationExtensionsClientInputsConfig registrationExtensions = new RegistrationExtensionsClientInputsConfig();
    private final AuthenticationExtensionsClientInputsConfig authenticationExtensions = new AuthenticationExtensionsClientInputsConfig();
    private OptionsProvider optionsProvider;
    private String rpId = null;
    private String rpName = null;
    private String rpIcon = null;
    private Long registrationTimeout;
    private Long authenticationTimeout;

    /**
     * Returns a new instance
     *
     * @return the {@link WebAuthnConfigurer}
     */
    public static WebAuthnConfigurer<HttpSecurity> webAuthn() {
        return new WebAuthnConfigurer<>();
    }

    // ~ Methods
    // ========================================================================================================


    /**
     * {@inheritDoc}
     */
    @Override
    public void init(H http) throws Exception {
        super.init(http);

        if (optionsProvider == null) {
            optionsProvider = WebAuthnConfigurerUtil.getOptionsProvider(http);
        }
        http.setSharedObject(OptionsProvider.class, optionsProvider);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void configure(H http) throws Exception {
        super.configure(http);

        if (rpId != null) {
            optionsProvider.setRpId(rpId);
        }
        if (rpName != null) {
            optionsProvider.setRpName(rpName);
        }
        if (rpIcon != null) {
            optionsProvider.setRpIcon(rpIcon);
        }
        optionsProvider.getPubKeyCredParams().addAll(publicKeyCredParamsConfig.publicKeyCredentialParameters);
        if (registrationTimeout != null) {
            optionsProvider.setRegistrationTimeout(registrationTimeout);
        }
        if (authenticationTimeout != null) {
            optionsProvider.setAuthenticationTimeout(authenticationTimeout);
        }
        optionsProvider.setRegistrationExtensions(registrationExtensions.builder.build());
        optionsProvider.setAuthenticationExtensions(authenticationExtensions.builder.build());
    }

    /**
     * The relying party id for credential scoping
     *
     * @param rpId the relying party id
     * @return the {@link WebAuthnConfigurer} for additional customization
     */
    public WebAuthnConfigurer<H> rpId(String rpId) {
        Assert.hasText(rpId, "rpId parameter must not be null or empty");
        this.rpId = rpId;
        return this;
    }

    /**
     * The relying party name
     *
     * @param rpName the relying party name
     * @return the {@link WebAuthnConfigurer} for additional customization
     */
    public WebAuthnConfigurer<H> rpName(String rpName) {
        Assert.hasText(rpName, "rpName parameter must not be null or empty");
        this.rpName = rpName;
        return this;
    }

    /**
     * The relying party icon
     *
     * @param rpIcon the relying party icon
     * @return the {@link WebAuthnConfigurer} for additional customization
     */
    public WebAuthnConfigurer<H> rpIcon(String rpIcon) {
        Assert.hasText(rpIcon, "rpIcon parameter must not be null or empty");
        this.rpIcon = rpIcon;
        return this;
    }

    /**
     * Returns the {@link PublicKeyCredParamsConfig} for configuring PublicKeyCredParams
     *
     * @return the {@link PublicKeyCredParamsConfig}
     */
    public WebAuthnConfigurer<H>.PublicKeyCredParamsConfig publicKeyCredParams() {
        return this.publicKeyCredParamsConfig;
    }

    /**
     * The timeout for registration ceremony
     *
     * @param registrationTimeout the timeout for registration ceremony
     * @return the {@link WebAuthnConfigurer} for additional customization
     */
    public WebAuthnConfigurer<H> registrationTimeout(Long registrationTimeout) {
        this.registrationTimeout = registrationTimeout;
        return this;
    }

    /**
     * The timeout for authentication ceremony
     *
     * @param authenticationTimeout the timeout for authentication ceremony
     * @return the {@link WebAuthnConfigurer} for additional customization
     */
    public WebAuthnConfigurer<H> authenticationTimeout(Long authenticationTimeout) {
        this.authenticationTimeout = authenticationTimeout;
        return this;
    }

    /**
     * Returns the {@link RegistrationExtensionsClientInputsConfig} for configuring registration extensions
     *
     * @return the {@link RegistrationExtensionsClientInputsConfig}
     */
    public WebAuthnConfigurer<H>.RegistrationExtensionsClientInputsConfig registrationExtensions() {
        return this.registrationExtensions;
    }

    /**
     * Returns the {@link AuthenticationExtensionsClientInputsConfig} for configuring authentication extensions
     *
     * @return the {@link AuthenticationExtensionsClientInputsConfig}
     */
    public WebAuthnConfigurer<H>.AuthenticationExtensionsClientInputsConfig authenticationExtensions() {
        return this.authenticationExtensions;
    }

    /**
     * Configuration options for PublicKeyCredParams
     */
    public class PublicKeyCredParamsConfig {

        private final List<PublicKeyCredentialParameters> publicKeyCredentialParameters = new ArrayList<>();

        private PublicKeyCredParamsConfig() {
        }

        /**
         * Add PublicKeyCredParam
         *
         * @param type the {@link PublicKeyCredentialType}
         * @param alg  the {@link COSEAlgorithmIdentifier}
         * @return the {@link PublicKeyCredParamsConfig}
         */
        public PublicKeyCredParamsConfig addPublicKeyCredParams(PublicKeyCredentialType type, COSEAlgorithmIdentifier alg) {
            Assert.notNull(type, "type must not be null");
            Assert.notNull(alg, "alg must not be null");

            publicKeyCredentialParameters.add(new PublicKeyCredentialParameters(type, alg));
            return this;
        }

        /**
         * Returns the {@link WebAuthnConfigurer} for further configuration.
         *
         * @return the {@link WebAuthnConfigurer}
         */
        public WebAuthnConfigurer<H> and() {
            return WebAuthnConfigurer.this;
        }

    }

    /**
     * Configuration options for AuthenticationExtensionsClientInputs
     */
    public class RegistrationExtensionsClientInputsConfig {

        private final AuthenticationExtensionsClientInputs.BuilderForRegistration builder = new AuthenticationExtensionsClientInputs.BuilderForRegistration();

        private RegistrationExtensionsClientInputsConfig() {
        }

        /**
         * Configure uvm extension
         *
         * @param uvm flag to enable uvm extension
         * @return the {@link RegistrationExtensionsClientInputsConfig}
         */
        public RegistrationExtensionsClientInputsConfig uvm(Boolean uvm) {
            Assert.notNull(uvm, "uvm must not be null");
            builder.setUvm(uvm);
            return this;
        }

        /**
         * Configure credProps extension
         *
         * @param credProps flag to enable uvm extension
         * @return the {@link RegistrationExtensionsClientInputsConfig}
         */
        public RegistrationExtensionsClientInputsConfig credProps(Boolean credProps){
            Assert.notNull(credProps, "credProps must not be null");
            builder.setCredProps(credProps);
            return this;
        }

        /**
         * Add custom entry
         *
         * @param key key
         * @param value value
         * @return the {@link RegistrationExtensionsClientInputsConfig}
         */
        public RegistrationExtensionsClientInputsConfig entry(String key, Serializable value) {
            Assert.notNull(key, "key must not be null");
            Assert.notNull(value, "value must not be null");
            builder.set(key, value);
            return this;
        }

        /**
         * Returns the {@link WebAuthnConfigurer} for further configuration.
         *
         * @return the {@link WebAuthnConfigurer}
         */
        public WebAuthnConfigurer<H> and() {
            return WebAuthnConfigurer.this;
        }
    }

    /**
     * Configuration options for AuthenticationExtensionsClientInputs
     */
    public class AuthenticationExtensionsClientInputsConfig {

        private final AuthenticationExtensionsClientInputs.BuilderForAuthentication builder = new AuthenticationExtensionsClientInputs.BuilderForAuthentication();

        private AuthenticationExtensionsClientInputsConfig() {
        }

        /**
         * Configure appid extension
         *
         * @param appid appid
         * @return the {@link AuthenticationExtensionsClientInputsConfig}
         */
        public AuthenticationExtensionsClientInputsConfig appid(String appid) {
            Assert.notNull(appid, "appid must not be null");
            builder.setAppid(appid);
            return this;
        }

        /**
         * Configure appidExclude extension
         *
         * @param appidExclude appid
         * @return the {@link AuthenticationExtensionsClientInputsConfig}
         */
        public AuthenticationExtensionsClientInputsConfig appidExclude(String appidExclude) {
            Assert.notNull(appidExclude, "appidExclude must not be null");
            builder.setAppidExclude(appidExclude);
            return this;
        }

        /**
         * Configure uvm extension
         *
         * @param uvm flag to enable uvm extension
         * @return the {@link AuthenticationExtensionsClientInputsConfig}
         */
        public AuthenticationExtensionsClientInputsConfig uvm(Boolean uvm) {
            Assert.notNull(uvm, "uvm must not be null");
            builder.setUvm(uvm);
            return this;
        }

        /**
         * Add custom entry
         *
         * @param key key
         * @param value value
         * @return the {@link AuthenticationExtensionsClientInputsConfig}
         */
        public AuthenticationExtensionsClientInputsConfig entry(String key, Serializable value) {
            Assert.notNull(key, "key must not be null");
            Assert.notNull(value, "value must not be null");
            builder.set(key, value);
            return this;
        }

        /**
         * Returns the {@link WebAuthnConfigurer} for further configuration.
         *
         * @return the {@link WebAuthnConfigurer}
         */
        public WebAuthnConfigurer<H> and() {
            return WebAuthnConfigurer.this;
        }
    }

}
