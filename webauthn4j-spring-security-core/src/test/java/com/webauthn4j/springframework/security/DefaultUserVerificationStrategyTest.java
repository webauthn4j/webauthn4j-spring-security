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

package com.webauthn4j.springframework.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class DefaultUserVerificationStrategyTest {

    @Test
    public void constructor_test(){
        DefaultUserVerificationStrategy target = new DefaultUserVerificationStrategy();
        assertThat(target.getTrustResolver()).isNotNull();
    }

    @Test
    public void getter_setter_test(){
        DefaultUserVerificationStrategy target = new DefaultUserVerificationStrategy();
        AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
        target.setTrustResolver(authenticationTrustResolver);
        assertThat(target.getTrustResolver()).isEqualTo(authenticationTrustResolver);
    }


    @Test
    public void isUserVerificationRequired_authentication_null_test(){
        DefaultUserVerificationStrategy target = new DefaultUserVerificationStrategy();
        SecurityContext securityContext = mock(SecurityContext.class);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);
        assertThat(target.isUserVerificationRequired()).isTrue();
    }

    @Test
    public void isUserVerificationRequired_authentication_AnonymousAuthenticationToken_test(){
        DefaultUserVerificationStrategy target = new DefaultUserVerificationStrategy();
        SecurityContext securityContext = mock(SecurityContext.class);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(new AnonymousAuthenticationToken("dummy", "dummy", Collections.singletonList(new SimpleGrantedAuthority("dummy"))));
        assertThat(target.isUserVerificationRequired()).isTrue();
    }

    @Test
    public void isUserVerificationRequired_authentication_authenticated_UsernamePasswordAuthenticationToken_test(){
        DefaultUserVerificationStrategy target = new DefaultUserVerificationStrategy();
        SecurityContext securityContext = mock(SecurityContext.class);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(new UsernamePasswordAuthenticationToken("dummy", "dummy", null));
        assertThat(target.isUserVerificationRequired()).isFalse();
    }

}