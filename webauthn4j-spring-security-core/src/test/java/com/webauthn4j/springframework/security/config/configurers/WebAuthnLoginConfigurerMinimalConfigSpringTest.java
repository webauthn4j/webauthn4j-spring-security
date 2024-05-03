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


import com.webauthn4j.springframework.security.credential.InMemoryWebAuthnCredentialRecordManager;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
public class WebAuthnLoginConfigurerMinimalConfigSpringTest {

    @Autowired
    FilterChainProxy springSecurityFilterChain;

    private MockMvc mvc;

    @Test
    public void rootPath_with_authenticated_user_test() throws Exception {
        mvc = MockMvcBuilders.standaloneSetup()
                .defaultRequest(get("/").with(user("john")))
                .addFilter(springSecurityFilterChain)
                .build();

        mvc
                .perform(get("/"))
                .andExpect(authenticated())
                .andExpect(status().isNotFound());

    }


    @Configuration
    @EnableWebSecurity
    static class Config {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

            http.with(WebAuthnLoginConfigurer.webAuthnLogin(), (customizer)->{});
            // Authorization
            http.authorizeHttpRequests(authorizeHttpRequestsCustomizer->{
                authorizeHttpRequestsCustomizer.requestMatchers("/login").permitAll();
                authorizeHttpRequestsCustomizer.anyRequest().authenticated();
            });


            return http.build();
        }

        @Configuration
        static class BeanConfig {
            @Bean
            public WebAuthnCredentialRecordService webAuthnAuthenticatorService(){
                return new InMemoryWebAuthnCredentialRecordManager();
            }

            @Bean(name = "mvcHandlerMappingIntrospector")
            public HandlerMappingIntrospector mvcHandlerMappingIntrospector() {
                return new HandlerMappingIntrospector();
            }

        }

    }
}
