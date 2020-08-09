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

import com.webauthn4j.springframework.security.exception.CredentialIdNotFoundException;
import com.webauthn4j.springframework.security.exception.PrincipalNotFoundException;
import com.webauthn4j.test.TestDataUtil;
import org.junit.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class InMemoryWebAuthnAuthenticatorManagerTest {

    private InMemoryWebAuthnAuthenticatorManager target = new InMemoryWebAuthnAuthenticatorManager();

    @Test
    public void updateCounter_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnAuthenticator webAuthnAuthenticator = new WebAuthnAuthenticatorImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createAuthenticator(webAuthnAuthenticator);
        byte[] credentialId = webAuthnAuthenticator.getAttestedCredentialData().getCredentialId();
        target.updateCounter(credentialId, 1);
        assertThat(target.loadAuthenticatorByCredentialId(credentialId).getCounter()).isEqualTo(1);
    }

    @Test
    public void createAuthenticator_loadAuthenticatorByCredentialId_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnAuthenticator webAuthnAuthenticator = new WebAuthnAuthenticatorImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createAuthenticator(webAuthnAuthenticator);
        byte[] credentialId = webAuthnAuthenticator.getAttestedCredentialData().getCredentialId();
        WebAuthnAuthenticator loaded = target.loadAuthenticatorByCredentialId(credentialId);
        assertThat(loaded).isEqualTo(webAuthnAuthenticator);
    }

    @Test
    public void loadAuthenticatorsByUserPrincipal_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnAuthenticator webAuthnAuthenticator = new WebAuthnAuthenticatorImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createAuthenticator(webAuthnAuthenticator);
        assertThat(target.loadAuthenticatorsByUserPrincipal(userDetails)).containsExactly(webAuthnAuthenticator);
    }

    @Test
    public void loadAuthenticatorsByUserPrincipal_with_non_existing_userPrincipal_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnAuthenticator webAuthnAuthenticator = new WebAuthnAuthenticatorImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createAuthenticator(webAuthnAuthenticator);
        assertThatThrownBy(()-> target.loadAuthenticatorsByUserPrincipal("nonExistingUserCredential")).isInstanceOf(PrincipalNotFoundException.class);
    }

    @Test
    public void deleteAuthenticator_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnAuthenticator webAuthnAuthenticator = new WebAuthnAuthenticatorImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createAuthenticator(webAuthnAuthenticator);
        byte[] credentialId = webAuthnAuthenticator.getAttestedCredentialData().getCredentialId();
        target.deleteAuthenticator(credentialId);
        assertThat(target.authenticatorExists(credentialId)).isFalse();
    }

    @Test
    public void deleteAuthenticator_with_non_existing_id_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnAuthenticator webAuthnAuthenticator = new WebAuthnAuthenticatorImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createAuthenticator(webAuthnAuthenticator);
        byte[] nonExistingCredentialId = new byte[]{ 0x01, 0x23};
        assertThatThrownBy(()->target.deleteAuthenticator(nonExistingCredentialId)).isInstanceOf(CredentialIdNotFoundException.class);
    }

    @Test
    public void authenticatorExists_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnAuthenticator webAuthnAuthenticator = new WebAuthnAuthenticatorImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createAuthenticator(webAuthnAuthenticator);
        byte[] credentialId = webAuthnAuthenticator.getAttestedCredentialData().getCredentialId();
        assertThat(target.authenticatorExists(credentialId)).isTrue();
    }

}