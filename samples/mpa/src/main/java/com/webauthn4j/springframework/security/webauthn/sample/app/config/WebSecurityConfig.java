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
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import com.webauthn4j.springframework.security.config.configurers.WebAuthnLoginConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Autowired
    private ApplicationContext applicationContext;

    @Bean
    public WebAuthnAuthenticationProvider webAuthnAuthenticationProvider(WebAuthnCredentialRecordService authenticatorService, WebAuthnManager webAuthnManager){
        return new WebAuthnAuthenticationProvider(authenticatorService, webAuthnManager);
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        return daoAuthenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers){
        return new ProviderManager(providers);
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            // ignore static resources
            web.ignoring().requestMatchers(
                    "/favicon.ico",
                    "/js/**",
                    "/css/**",
                    "/webjars/**");
        };
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        // WebAuthn Login
        http.with(WebAuthnLoginConfigurer.webAuthnLogin(), (customizer)-> {
            customizer
                    .defaultSuccessUrl("/", true)
                    .failureUrl("/login")
                    .attestationOptionsEndpoint()
                    .rp()
                    .name("WebAuthn4J Spring Security Sample")
                    .and()
                    .pubKeyCredParams(
                            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1)
                    )
                    .attestation(AttestationConveyancePreference.NONE)
                    .extensions()
                    .uvm(true)
                    .credProps(true)
                    .extensionProviders()
                    .and()
                    .assertionOptionsEndpoint()
                    .extensions()
                    .extensionProviders();
        });

        http.headers(headers -> {
            // 'publickey-credentials-get *' allows getting WebAuthn credentials to all nested browsing contexts (iframes) regardless of their origin.
            headers.permissionsPolicy(config -> config.policy("publickey-credentials-get *"));
            // Disable "X-Frame-Options" to allow cross-origin iframe access
            headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable);
        });


        // Authorization
        http.authorizeHttpRequests(authz -> authz
                .requestMatchers(HttpMethod.GET, "/login").permitAll()
                .requestMatchers(HttpMethod.GET, "/signup").permitAll()
                .requestMatchers(HttpMethod.POST, "/signup").permitAll()
                .anyRequest().access(getWebExpressionAuthorizationManager("@webAuthnSecurityExpression.isWebAuthnAuthenticated(authentication) || hasAuthority('SINGLE_FACTOR_AUTHN_ALLOWED')"))
        );

        http.exceptionHandling(customizer -> {
            customizer.accessDeniedHandler((request, response, accessDeniedException) -> response.sendRedirect("/login"));
        });


        http.authenticationManager(authenticationManager);

        // As WebAuthn has its own CSRF protection mechanism (challenge), CSRF token is disabled here
        http.csrf(customizer -> {
            customizer.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
            customizer.ignoringRequestMatchers("/webauthn/**");
        });

        return http.build();

    }

    private WebExpressionAuthorizationManager getWebExpressionAuthorizationManager(final String expression) {
        DefaultHttpSecurityExpressionHandler expressionHandler = new DefaultHttpSecurityExpressionHandler();
        expressionHandler.setApplicationContext(applicationContext);
        WebExpressionAuthorizationManager authorizationManager = new WebExpressionAuthorizationManager(expression);
        authorizationManager.setExpressionHandler(expressionHandler);
        return authorizationManager;
    }
}
