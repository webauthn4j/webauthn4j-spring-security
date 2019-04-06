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

package net.sharplab.springframework.security.webauthn.config.configurers;

import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import net.sharplab.springframework.security.webauthn.WebAuthnAuthenticationProvider;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;

import java.util.Collections;
import java.util.List;

public class WebAuthnAuthenticationProviderConfigurer<
        B extends ProviderManagerBuilder<B>,
        U extends WebAuthnUserDetailsService,
        A extends WebAuthnAuthenticatorService,
        V extends WebAuthnAuthenticationContextValidator>
        extends SecurityConfigurerAdapter<AuthenticationManager, B> {

    //~ Instance fields
    // ================================================================================================
    private U userDetailsService;
    private A authenticatorService;
    private WebAuthnAuthenticationContextValidator authenticationContextValidator;
    private List<String> expectedAuthenticationExtensionIds = Collections.emptyList();

    /**
     * Constructor
     *
     * @param userDetailsService   {@link WebAuthnUserDetailsService}
     * @param authenticatorService {@link WebAuthnAuthenticatorService}
     */
    public WebAuthnAuthenticationProviderConfigurer(U userDetailsService, A authenticatorService, V authenticationContextValidator) {
        this.userDetailsService = userDetailsService;
        this.authenticatorService = authenticatorService;
        this.authenticationContextValidator = authenticationContextValidator;
    }

    @Override
    public void configure(B builder) {
        WebAuthnAuthenticationProvider authenticationProvider =
                new WebAuthnAuthenticationProvider(userDetailsService, authenticatorService, authenticationContextValidator);
        authenticationProvider.setExpectedAuthenticationExtensionIds(expectedAuthenticationExtensionIds);
        authenticationProvider = postProcess(authenticationProvider);
        builder.authenticationProvider(authenticationProvider);
    }

    public void expectedAuthenticationExtensionIds(List<String> expectedAuthenticationExtensionIds){
        this.expectedAuthenticationExtensionIds = expectedAuthenticationExtensionIds;
    }

}
