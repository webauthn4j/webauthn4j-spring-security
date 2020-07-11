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

import org.junit.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnSecurityExpressionTest {

    @Test
    public void isWebAuthnAuthenticated_test(){
        WebAuthnSecurityExpression target = new WebAuthnSecurityExpression();
        assertThat(target.isWebAuthnAuthenticated(null)).isFalse();
        assertThat(target.isWebAuthnAuthenticated(new WebAuthnAuthenticationToken(null, null, null))).isTrue();
        assertThat(target.isWebAuthnAuthenticated(new AnonymousAuthenticationToken("dummy", "dummy", Collections.singletonList(new SimpleGrantedAuthority("dummy"))))).isFalse();
    }

}