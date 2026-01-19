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

import com.webauthn4j.springframework.security.credential.InMemoryWebAuthnCredentialRecordManager;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecord;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordImpl;
import com.webauthn4j.springframework.security.exception.CredentialIdNotFoundException;
import com.webauthn4j.springframework.security.exception.PrincipalNotFoundException;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class InMemoryWebAuthnCredentialRecordManagerTest {

    private InMemoryWebAuthnCredentialRecordManager target = new InMemoryWebAuthnCredentialRecordManager();

    @Test
    public void updateCounter_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnCredentialRecord webAuthnCredentialRecord = new WebAuthnCredentialRecordImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createCredentialRecord(webAuthnCredentialRecord);
        byte[] credentialId = webAuthnCredentialRecord.getAttestedCredentialData().getCredentialId();
        target.updateCounter(credentialId, 1);
        assertThat(target.loadCredentialRecordByCredentialId(credentialId).getCounter()).isEqualTo(1);
    }

    @Test
    public void createCredentialRecord_loadCredentialRecordByCredentialId_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnCredentialRecord webAuthnCredentialRecord = new WebAuthnCredentialRecordImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createCredentialRecord(webAuthnCredentialRecord);
        byte[] credentialId = webAuthnCredentialRecord.getAttestedCredentialData().getCredentialId();
        WebAuthnCredentialRecord loaded = target.loadCredentialRecordByCredentialId(credentialId);
        assertThat(loaded).isEqualTo(webAuthnCredentialRecord);
    }

    @Test
    public void loadCredentialRecordsByUserPrincipal_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnCredentialRecord webAuthnCredentialRecord = new WebAuthnCredentialRecordImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createCredentialRecord(webAuthnCredentialRecord);
        assertThat(target.loadCredentialRecordsByUserPrincipal(userDetails)).containsExactly(webAuthnCredentialRecord);
    }

    @Test
    public void loadCredentialRecordsByUserPrincipal_with_non_existing_userPrincipal_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnCredentialRecord webAuthnCredentialRecord = new WebAuthnCredentialRecordImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createCredentialRecord(webAuthnCredentialRecord);
        assertThatThrownBy(()-> target.loadCredentialRecordsByUserPrincipal("nonExistingUserCredential")).isInstanceOf(PrincipalNotFoundException.class);
    }

    @Test
    public void deleteCredentialRecord_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnCredentialRecord webAuthnCredentialRecord = new WebAuthnCredentialRecordImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createCredentialRecord(webAuthnCredentialRecord);
        byte[] credentialId = webAuthnCredentialRecord.getAttestedCredentialData().getCredentialId();
        target.deleteCredentialRecord(credentialId);
        assertThat(target.credentialRecordExists(credentialId)).isFalse();
    }

    @Test
    public void deleteCredentialRecord_with_non_existing_id_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnCredentialRecord webAuthnCredentialRecord = new WebAuthnCredentialRecordImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createCredentialRecord(webAuthnCredentialRecord);
        byte[] nonExistingCredentialId = new byte[]{ 0x01, 0x23};
        assertThatThrownBy(()->target.deleteCredentialRecord(nonExistingCredentialId)).isInstanceOf(CredentialIdNotFoundException.class);
    }

    @Test
    public void credentialRecordExists_test(){
        String authenticatorName = "authenticator";
        UserDetails userDetails = new User("user", "password", Collections.emptyList());
        WebAuthnCredentialRecord webAuthnCredentialRecord = new WebAuthnCredentialRecordImpl(authenticatorName, userDetails, TestDataUtil.createAttestedCredentialData(), TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement().getAttestationStatement(), 0);
        target.createCredentialRecord(webAuthnCredentialRecord);
        byte[] credentialId = webAuthnCredentialRecord.getAttestedCredentialData().getCredentialId();
        assertThat(target.credentialRecordExists(credentialId)).isTrue();
    }

}