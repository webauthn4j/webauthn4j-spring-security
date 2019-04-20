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


import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.test.TestDataUtil;
import net.sharplab.springframework.security.webauthn.WebAuthnProcessingFilter;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.options.OptionsProvider;
import net.sharplab.springframework.security.webauthn.options.OptionsProviderImpl;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collection;
import java.util.Collections;

import static net.sharplab.springframework.security.webauthn.config.configurers.WebAuthnConfigurer.webAuthn;
import static net.sharplab.springframework.security.webauthn.config.configurers.WebAuthnLoginConfigurer.webAuthnLogin;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(SpringRunner.class)
public class WebAuthnLoginConfigurerSetterSpringTest {

    @Autowired
    FilterChainProxy springSecurityFilterChain;

    private MockMvc mvc;

    @MockBean
    private WebAuthnUserDetailsService userDetailsService;

    @Autowired
    private ServerPropertyProvider serverPropertyProvider;

    @SuppressWarnings("unchecked")
    @Before
    public void setup() {
        WebAuthnUserDetails mockUserDetails = mock(WebAuthnUserDetails.class);
        Collection authenticators = Collections.singletonList(TestDataUtil.createAuthenticator());
        when(mockUserDetails.getAuthenticators()).thenReturn(authenticators);
        when(mockUserDetails.getUserHandle()).thenReturn(new byte[32]);
        doThrow(new UsernameNotFoundException(null)).when(userDetailsService).loadUserByUsername(null);
        when(userDetailsService.loadUserByUsername(anyString())).thenReturn(mockUserDetails);
    }

    @Test
    public void configured_filter_test() {
        WebAuthnProcessingFilter webAuthnProcessingFilter = (WebAuthnProcessingFilter) springSecurityFilterChain.getFilterChains().get(0).getFilters().stream().filter(item -> item instanceof WebAuthnProcessingFilter).findFirst().orElse(null);
        ;
        assertThat(webAuthnProcessingFilter.getServerPropertyProvider()).isEqualTo(serverPropertyProvider);
    }

    @EnableWebSecurity
    static class Config extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            // Authentication
            http.apply(webAuthn());

            http.apply(webAuthnLogin());

            // Authorization
            http.authorizeRequests()
                    .antMatchers("/login").permitAll()
                    .anyRequest().authenticated();
        }

        @Configuration
        static class BeanConfig {

            @Bean
            public JsonConverter jsonConverter(){
                return new JsonConverter();
            }

            @Bean
            public ChallengeRepository challengeRepository() {
                ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
                when(challengeRepository.loadOrGenerateChallenge(any())).thenReturn(new DefaultChallenge("aFglXMZdQTKD4krvNzJBzA"));
                return challengeRepository;
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

        }

    }
}
