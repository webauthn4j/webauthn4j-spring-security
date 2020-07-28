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

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationProvider;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.util.Assert;

/**
 * Allows configuring a {@link WebAuthnAuthenticationProvider}
 *
 * @see WebAuthnConfigurer
 */
public class WebAuthnAuthenticationProviderConfigurer<
        B extends ProviderManagerBuilder<B>,
        A extends WebAuthnAuthenticatorService,
        V extends WebAuthnManager>
        extends SecurityConfigurerAdapter<AuthenticationManager, B> {

    //~ Instance fields
    // ================================================================================================
    private A webAuthnAuthenticatorService;
    private final V webAuthnManager;

    /**
     * Constructor
     *
     * @param webAuthnAuthenticatorService {@link WebAuthnAuthenticatorService}
     * @param webAuthnManager      {@link WebAuthnManager}
     */
    public WebAuthnAuthenticationProviderConfigurer(A webAuthnAuthenticatorService, V webAuthnManager) {

        Assert.notNull(webAuthnAuthenticatorService, "webAuthnAuthenticatorService must not be null");
        Assert.notNull(webAuthnManager, "webAuthnManager must not be null");

        this.webAuthnAuthenticatorService = webAuthnAuthenticatorService;
        this.webAuthnManager = webAuthnManager;
    }

    // ~ Methods
    // ========================================================================================================

    @Override
    public void configure(B builder) {
        WebAuthnAuthenticationProvider authenticationProvider = new WebAuthnAuthenticationProvider(webAuthnAuthenticatorService, webAuthnManager);
        authenticationProvider = postProcess(authenticationProvider);
        builder.authenticationProvider(authenticationProvider);
    }

}
