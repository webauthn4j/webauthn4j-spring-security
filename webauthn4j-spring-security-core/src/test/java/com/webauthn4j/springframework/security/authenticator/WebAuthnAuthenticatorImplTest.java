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

package com.webauthn4j.springframework.security.authenticator;

import org.junit.Test;
import org.springframework.security.core.userdetails.UserDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class WebAuthnAuthenticatorImplTest {

    @Test
    public void equals_hashCode_test() {
        WebAuthnAuthenticatorImpl instanceA = new WebAuthnAuthenticatorImpl("authenticator", null, null, 0);
        WebAuthnAuthenticatorImpl instanceB = new WebAuthnAuthenticatorImpl("authenticator", null, null, 0);
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

    @Test
    public void get_set_userPrincipal_test() {
        WebAuthnAuthenticatorImpl instance = new WebAuthnAuthenticatorImpl("authenticator", null, null, 0);
        UserDetails userDetails = mock(UserDetails.class);
        instance.setUserPrincipal(userDetails);
        assertThat(instance.getUserPrincipal()).isEqualTo(userDetails);
    }

    @Test
    public void get_set_name_test() {
        WebAuthnAuthenticatorImpl instance = new WebAuthnAuthenticatorImpl("authenticator", null, null, 0);
        assertThat(instance.getName()).isEqualTo("authenticator");
        instance.setName("newName");
        assertThat(instance.getName()).isEqualTo("newName");
    }
}
