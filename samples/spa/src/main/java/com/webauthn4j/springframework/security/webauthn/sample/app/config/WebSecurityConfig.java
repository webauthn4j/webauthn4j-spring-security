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
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationProvider;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.config.configurers.WebAuthnLoginConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.List;


/**
 * Security Configuration
 */
@Configuration
@Import(value = WebSecurityBeanConfig.class)
@EnableWebSecurity
public class WebSecurityConfig {

    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;

    @Autowired
    private LogoutSuccessHandler logoutSuccessHandler;

    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;

    @Bean
    public WebAuthnAuthenticationProvider webAuthnAuthenticationProvider(WebAuthnAuthenticatorService authenticatorService, WebAuthnManager webAuthnManager){
        return new WebAuthnAuthenticationProvider(authenticatorService, webAuthnManager);
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder());
        return daoAuthenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers){
        return new ProviderManager(providers);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        // WebAuthn Login
        http.apply(WebAuthnLoginConfigurer.webAuthnLogin())
                .usernameParameter("username")
                .passwordParameter("password")
                .credentialIdParameter("credentialId")
                .clientDataJSONParameter("clientDataJSON")
                .authenticatorDataParameter("authenticatorData")
                .signatureParameter("signature")
                .clientExtensionsJSONParameter("clientExtensionsJSON")
                .loginProcessingUrl("/login")
                .attestationOptionsEndpoint()
                .rp()
                .name("WebAuthn4J Spring Security Sample")
                .and()
                .pubKeyCredParams(
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256), // Windows Hello
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256) // FIDO U2F Key, etc
                )
                .extensions()
                .credProps(true)
                .and()
                .assertionOptionsEndpoint()
                .and()
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .and()
                .authenticationManager(authenticationManager);

        http.headers(headers -> {
            // 'publickey-credentials-get *' allows getting WebAuthn credentials to all nested browsing contexts (iframes) regardless of their origin.
            headers.permissionsPolicy(config -> config.policy("publickey-credentials-get *"));
            // Disable "X-Frame-Options" to allow cross-origin iframe access
            headers.frameOptions().disable();
        });

        // Logout
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(logoutSuccessHandler);

        // Authorization
        http.authorizeRequests()
                .mvcMatchers("/").permitAll()
                .mvcMatchers("/static/**").permitAll()
                .mvcMatchers("/angular/**").permitAll()
                .mvcMatchers("/webjars/**").permitAll()
                .mvcMatchers("/favicon.ico").permitAll()
                .mvcMatchers("/api/auth/status").permitAll()
                .mvcMatchers(HttpMethod.GET, "/login").permitAll()
                .mvcMatchers(HttpMethod.POST, "/api/profile").permitAll()
                .mvcMatchers("/health/**").permitAll()
                .mvcMatchers("/info/**").permitAll()
                .mvcMatchers("/h2-console/**").denyAll()
                .mvcMatchers("/api/admin/**").access("hasRole('ADMIN_ROLE') and isAuthenticated()")
                .anyRequest().access("@webAuthnSecurityExpression.isWebAuthnAuthenticated(authentication) || hasAuthority('SINGLE_FACTOR_AUTHN_ALLOWED')");

        http.sessionManagement()
                .sessionAuthenticationFailureHandler(authenticationFailureHandler);

        http.exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler);

        // As WebAuthn has its own CSRF protection mechanism (challenge), CSRF token is disabled here
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        http.csrf().ignoringAntMatchers("/webauthn/**");

        return http.build();
    }
}
