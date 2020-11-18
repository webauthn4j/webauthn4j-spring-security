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

import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import org.junit.Test;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class WebAuthnAuthenticatorImplTest {

    @Test
    public void equals_hashCode_test() {
        Serializable userPrincipal = mock(Serializable.class);
        AttestedCredentialData attestedCredentialData = mock(AttestedCredentialData.class);
        AttestationStatement attestationStatement = mock(AttestationStatement.class);
        WebAuthnAuthenticatorImpl instanceA = new WebAuthnAuthenticatorImpl("authenticator", userPrincipal, attestedCredentialData, attestationStatement, 0);
        WebAuthnAuthenticatorImpl instanceB = new WebAuthnAuthenticatorImpl("authenticator", userPrincipal, attestedCredentialData, attestationStatement, 0);
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

    @Test
    public void get_set_userPrincipal_test() {
        UserDetails userDetails = mock(UserDetails.class);
        WebAuthnAuthenticatorImpl instance = new WebAuthnAuthenticatorImpl("authenticator", userDetails, mock(AttestedCredentialData.class), mock(AttestationStatement.class), 0);
        assertThat(instance.getUserPrincipal()).isEqualTo(userDetails);
    }

    @Test
    public void get_set_name_test() {
        WebAuthnAuthenticatorImpl instance = new WebAuthnAuthenticatorImpl("authenticator", mock(Serializable.class), mock(AttestedCredentialData.class), mock(AttestationStatement.class), 0);
        assertThat(instance.getName()).isEqualTo("authenticator");
        instance.setName("newName");
        assertThat(instance.getName()).isEqualTo("newName");
    }
}
