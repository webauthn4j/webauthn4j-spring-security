/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.config.configurers;

import net.sharplab.springframework.security.webauthn.WebAuthnMultiFactorAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @param <B> the type of the {@link SecurityBuilder}
 * @param <C> the type of {@link WebAuthnMultiFactorAuthenticationConfigurer} this is
 * @param <U> The type of {@link UserDetailsService} that is being used
 */
public class WebAuthnMultiFactorAuthenticationConfigurer<B extends ProviderManagerBuilder<B>, C extends WebAuthnMultiFactorAuthenticationConfigurer<B, C, U>, U extends UserDetailsService>
        extends SecurityConfigurerAdapter<AuthenticationManager, B> {

    //~ Instance fields
    // ================================================================================================
    private AuthenticationProvider authenticationProvider;

    public WebAuthnMultiFactorAuthenticationConfigurer(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public void configure(B builder) {
        WebAuthnMultiFactorAuthenticationProvider delegatingAuthenticationProvider = new WebAuthnMultiFactorAuthenticationProvider(authenticationProvider);
        delegatingAuthenticationProvider = postProcess(delegatingAuthenticationProvider);
        builder.authenticationProvider(delegatingAuthenticationProvider);
    }
}
