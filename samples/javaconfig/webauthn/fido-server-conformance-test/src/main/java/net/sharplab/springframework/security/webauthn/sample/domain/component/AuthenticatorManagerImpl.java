/*
 *    Copyright 2002-2019 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.sample.domain.component;

import net.sharplab.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.AuthenticatorEntityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@Component
public class AuthenticatorManagerImpl implements AuthenticatorManager {

    private Logger logger = LoggerFactory.getLogger(AuthenticatorManagerImpl.class);

    private AuthenticatorEntityRepository authenticatorEntityRepository;

    public AuthenticatorManagerImpl(AuthenticatorEntityRepository authenticatorEntityRepository) {
        this.authenticatorEntityRepository = authenticatorEntityRepository;
    }

    @Override
    public void updateCounter(byte[] credentialId, long counter) throws CredentialIdNotFoundException {
        AuthenticatorEntity authenticatorEntity = authenticatorEntityRepository.findOneByCredentialId(credentialId)
                .orElseThrow(() -> new CredentialIdNotFoundException("AuthenticatorEntity not found"));
        authenticatorEntity.setCounter(counter);
    }

}
