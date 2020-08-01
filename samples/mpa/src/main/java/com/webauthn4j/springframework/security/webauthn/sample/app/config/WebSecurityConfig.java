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

package com.webauthn4j.springframework.security.webauthn.sample.app.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private WebAuthnAuthenticatorService webAuthnAuthenticatorService;

    @Autowired
    private WebAuthnManager webAuthnManager;

    @Autowired
    private UserDetailsService userDetailsService;

//    @Override
//    public void configure(AuthenticationManagerBuilder builder) throws Exception {
////        builder.apply(new WebAuthnAuthenticationProviderConfigurer<>(webAuthnAuthenticatorService, webAuthnManager));
////        builder.userDetailsService(userDetailsService);
//    }

    @Override
    public void configure(WebSecurity web) {
        // ignore static resources
        web.ignoring().antMatchers(
                "/favicon.ico",
                "/static/**",
                "/webjars/**");
    }

    /**
     * Configure SecurityFilterChain
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().permitAll();
    }
}
