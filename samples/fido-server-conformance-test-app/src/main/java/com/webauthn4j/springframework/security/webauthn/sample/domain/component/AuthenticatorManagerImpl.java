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

package com.webauthn4j.springframework.security.webauthn.sample.domain.component;

import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorImpl;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.exception.CredentialIdNotFoundException;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import com.webauthn4j.springframework.security.webauthn.sample.domain.repository.AuthenticatorEntityRepository;
import com.webauthn4j.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Transactional
@Component
public class AuthenticatorManagerImpl implements WebAuthnAuthenticatorManager {

    private final Logger logger = LoggerFactory.getLogger(AuthenticatorManagerImpl.class);

    private final AuthenticatorEntityRepository authenticatorEntityRepository;
    private final UserEntityRepository userEntityRepository;

    public AuthenticatorManagerImpl(AuthenticatorEntityRepository authenticatorEntityRepository, UserEntityRepository userEntityRepository) {
        this.authenticatorEntityRepository = authenticatorEntityRepository;
        this.userEntityRepository = userEntityRepository;
    }

    @SuppressWarnings("java:S1130")
    @Override
    public void updateCounter(byte[] credentialId, long counter) throws CredentialIdNotFoundException {
        AuthenticatorEntity authenticatorEntity = authenticatorEntityRepository.findOneByCredentialId(credentialId)
                .orElseThrow(() -> new CredentialIdNotFoundException("AuthenticatorEntity not found"));
        authenticatorEntity.setCounter(counter);
    }

    @Override
    public WebAuthnAuthenticator loadAuthenticatorByCredentialId(byte[] credentialId) {
        return authenticatorEntityRepository.findOneByCredentialId(credentialId)
                .orElseThrow(() -> new CredentialIdNotFoundException("AuthenticatorEntity not found"));
    }

    @Override
    public List<WebAuthnAuthenticator> loadAuthenticatorsByUserPrincipal(Object principal) {
        return new ArrayList<>(authenticatorEntityRepository.findAllByEmailAddress((String) principal));
    }

    @Override
    public void createAuthenticator(WebAuthnAuthenticator webAuthnAuthenticator) {
        authenticatorEntityRepository.findOneByCredentialId(webAuthnAuthenticator.getAttestedCredentialData().getCredentialId())
                .ifPresent((retrievedAuthenticatorEntity) -> {
                    throw new WebAuthnSampleBusinessException("Authenticator is not found.");
                });

        AuthenticatorEntity authenticatorEntity = new AuthenticatorEntity();

        if(webAuthnAuthenticator.getUserPrincipal() != null){
            String username = ((UserDetails)webAuthnAuthenticator.getUserPrincipal()).getUsername();
            userEntityRepository.findOneByEmailAddress(username).ifPresent(authenticatorEntity::setUser);
        }

        String authenticatorName;
        if(webAuthnAuthenticator instanceof WebAuthnAuthenticatorImpl){
            authenticatorName = ((WebAuthnAuthenticatorImpl) webAuthnAuthenticator).getName();
        }
        else {
            authenticatorName = "Authenticator";
        }
        authenticatorEntity.setName(authenticatorName);
        authenticatorEntity.setCounter(webAuthnAuthenticator.getCounter());
        authenticatorEntity.setTransports(webAuthnAuthenticator.getTransports());
        authenticatorEntity.setAttestedCredentialData(webAuthnAuthenticator.getAttestedCredentialData());
        authenticatorEntity.setAttestationStatement(webAuthnAuthenticator.getAttestationStatement());
        authenticatorEntity.setClientExtensions(webAuthnAuthenticator.getClientExtensions());
        authenticatorEntity.setAuthenticatorExtensions(webAuthnAuthenticator.getAuthenticatorExtensions());
        authenticatorEntityRepository.save(authenticatorEntity);
    }

    @SuppressWarnings("java:S1130")
    @Override
    public void deleteAuthenticator(byte[] credentialId) throws CredentialIdNotFoundException {
        Optional<AuthenticatorEntity> optional = authenticatorEntityRepository.findOneByCredentialId(credentialId);
        if(optional.isPresent()){
            authenticatorEntityRepository.deleteById(optional.get().getId());
        }
        else {
            throw new CredentialIdNotFoundException("Authenticator is not found.");
        }
    }

    @Override
    public boolean authenticatorExists(byte[] credentialId) {
        return authenticatorEntityRepository.findOneByCredentialId(credentialId).isPresent();
    }
}
