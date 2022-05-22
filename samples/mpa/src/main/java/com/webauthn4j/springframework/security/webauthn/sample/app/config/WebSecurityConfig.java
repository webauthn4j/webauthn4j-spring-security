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
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationProvider;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.config.configurers.WebAuthnLoginConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public WebAuthnAuthenticationProvider webAuthnAuthenticationProvider(WebAuthnAuthenticatorService authenticatorService, WebAuthnManager webAuthnManager){
        return new WebAuthnAuthenticationProvider(authenticatorService, webAuthnManager);
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers){
        return new ProviderManager(providers);
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            // ignore static resources
            web.ignoring().antMatchers(
                    "/favicon.ico",
                    "/js/**",
                    "/css/**",
                    "/webjars/**");
        };
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        // WebAuthn Login
        http.apply(WebAuthnLoginConfigurer.webAuthnLogin())
                .defaultSuccessUrl("/", true)
                .failureUrl("/login")
                .attestationOptionsEndpoint()
                .rp()
                .name("WebAuthn4J Spring Security Sample MPA")
                .and()
                .pubKeyCredParams(
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1)
                )
                .attestation(AttestationConveyancePreference.DIRECT)
                .extensions()
                .uvm(true)
                .credProps(true)
                .extensionProviders()
                .and()
                .assertionOptionsEndpoint()
                .extensions()
                .extensionProviders();

        http.headers(headers -> {
            // 'publickey-credentials-get *' allows getting WebAuthn credentials to all nested browsing contexts (iframes) regardless of their origin.
            headers.permissionsPolicy(config -> config.policy("publickey-credentials-get *"));
            // Disable "X-Frame-Options" to allow cross-origin iframe access
            headers.frameOptions().disable();
        });


        // Authorization
        http.authorizeRequests()
                .mvcMatchers(HttpMethod.GET, "/login").permitAll()
                .mvcMatchers(HttpMethod.GET, "/signup").permitAll()
                .mvcMatchers(HttpMethod.POST, "/signup").permitAll()
                .anyRequest().access("@webAuthnSecurityExpression.isWebAuthnAuthenticated(authentication) || hasAuthority('SINGLE_FACTOR_AUTHN_ALLOWED')");

        http.exceptionHandling()
                .accessDeniedHandler((request, response, accessDeniedException) -> response.sendRedirect("/login"));

        http.authenticationManager(authenticationManager);

        // As WebAuthn has its own CSRF protection mechanism (challenge), CSRF token is disabled here
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        http.csrf().ignoringAntMatchers("/webauthn/**");

        return http.build();

    }
}
