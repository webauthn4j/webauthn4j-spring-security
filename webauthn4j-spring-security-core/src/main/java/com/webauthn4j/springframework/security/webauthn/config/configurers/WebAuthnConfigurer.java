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

package com.webauthn4j.springframework.security.webauthn.config.configurers;

import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.ExtensionClientInput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.springframework.security.webauthn.options.OptionsProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
 * @see WebAuthnLoginConfigurer
 * @see WebAuthnAuthenticationProviderConfigurer
 */
public class WebAuthnConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<WebAuthnConfigurer<H>, H> {

    private final WebAuthnConfigurer<H>.PublicKeyCredParamsConfig publicKeyCredParamsConfig = new WebAuthnConfigurer<H>.PublicKeyCredParamsConfig();
    private final ExtensionsClientInputsConfig<RegistrationExtensionClientInput> registrationExtensions
            = new ExtensionsClientInputsConfig<>();
    private final ExtensionsClientInputsConfig<AuthenticationExtensionClientInput> authenticationExtensions
            = new ExtensionsClientInputsConfig<>();
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
        optionsProvider.setRegistrationExtensions(new AuthenticationExtensionsClientInputs<>(registrationExtensions.extensionsClientInputs));
        optionsProvider.setAuthenticationExtensions(new AuthenticationExtensionsClientInputs<>(authenticationExtensions.extensionsClientInputs));
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
     * Returns the {@link ExtensionsClientInputsConfig} for configuring registration extensions
     *
     * @return the {@link ExtensionsClientInputsConfig}
     */
    public WebAuthnConfigurer<H>.ExtensionsClientInputsConfig<RegistrationExtensionClientInput> registrationExtensions() {
        return this.registrationExtensions;
    }

    /**
     * Returns the {@link ExtensionsClientInputsConfig} for configuring authentication extensions
     *
     * @return the {@link ExtensionsClientInputsConfig}
     */
    public WebAuthnConfigurer<H>.ExtensionsClientInputsConfig<AuthenticationExtensionClientInput> authenticationExtensions() {
        return this.authenticationExtensions;
    }

    /**
     * Configuration options for PublicKeyCredParams
     */
    public class PublicKeyCredParamsConfig {

        private List<PublicKeyCredentialParameters> publicKeyCredentialParameters = new ArrayList<>();

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
    public class ExtensionsClientInputsConfig<T extends ExtensionClientInput> {

        private Map<String, T> extensionsClientInputs = new HashMap<>();

        private ExtensionsClientInputsConfig() {
        }

        /**
         * Add AuthenticationExtensionClientInput
         *
         * @param extensionClientInput the T
         * @return the {@link ExtensionsClientInputsConfig}
         */
        public ExtensionsClientInputsConfig<T> addExtension(T extensionClientInput) {
            Assert.notNull(extensionClientInput, "extensionClientInput must not be null");
            extensionsClientInputs.put(extensionClientInput.getIdentifier(), extensionClientInput);
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
