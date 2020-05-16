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

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.springframework.security.webauthn.WebAuthnAuthenticationProvider;
import com.webauthn4j.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.webauthn.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.webauthn.options.OptionsProvider;
import com.webauthn4j.springframework.security.webauthn.options.OptionsProviderImpl;
import com.webauthn4j.springframework.security.webauthn.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import com.webauthn4j.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
public class WebAuthnAuthenticationProviderConfigurerSpringTest {

    @Autowired
    ProviderManager providerManager;

    @Test
    public void test() {
        assertThat(providerManager.getProviders()).extracting("class").contains(WebAuthnAuthenticationProvider.class);
    }

    @EnableWebSecurity
    static class Config extends WebSecurityConfigurerAdapter {

        @MockBean
        private WebAuthnUserDetailsService userDetailsService;

        @MockBean
        private WebAuthnAuthenticatorService authenticatorService;

        @Bean
        public ChallengeRepository challengeRepository() {
            return new HttpSessionChallengeRepository();
        }

        @Bean
        public OptionsProvider optionsProvider(WebAuthnUserDetailsService webAuthnUserDetailsService, ChallengeRepository challengeRepository) {
            OptionsProvider optionsProvider = new OptionsProviderImpl(webAuthnUserDetailsService, challengeRepository);
            optionsProvider.setRpId("example.com");
            return optionsProvider;
        }

        @Bean
        public ServerPropertyProvider serverPropertyProvider(OptionsProvider optionsProvider, ChallengeRepository challengeRepository) {
            return new ServerPropertyProviderImpl(optionsProvider, challengeRepository);
        }

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManager();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            // Authentication
            http.apply(WebAuthnLoginConfigurer.webAuthnLogin());

            // Authorization
            http.authorizeRequests()
                    .antMatchers("/login").permitAll()
                    .anyRequest().authenticated();
        }

        @Override
        public void configure(AuthenticationManagerBuilder builder) throws Exception {
            builder.apply(new WebAuthnAuthenticationProviderConfigurer<>(userDetailsService, authenticatorService, WebAuthnManager.createNonStrictWebAuthnManager()));
        }

    }

}
