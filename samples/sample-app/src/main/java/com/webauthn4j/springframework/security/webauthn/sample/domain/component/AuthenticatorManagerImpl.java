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
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.exception.CredentialIdNotFoundException;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.repository.AuthenticatorEntityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Transactional
@Component
public class AuthenticatorManagerImpl implements WebAuthnAuthenticatorService {

    private final Logger logger = LoggerFactory.getLogger(AuthenticatorManagerImpl.class);

    private final AuthenticatorEntityRepository authenticatorEntityRepository;

    public AuthenticatorManagerImpl(AuthenticatorEntityRepository authenticatorEntityRepository) {
        this.authenticatorEntityRepository = authenticatorEntityRepository;
    }

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
        String username;
        if(principal == null){
            return Collections.emptyList();
        }
        else if(principal instanceof String){
            username = (String) principal;
        }
        else if(principal instanceof Authentication){
            username = ((Authentication) principal).getName();
        }
        else {
            throw new IllegalArgumentException("unexpected principal is specified.");
        }
        return new ArrayList<>(authenticatorEntityRepository.findAllByEmailAddress(username));
    }
}
