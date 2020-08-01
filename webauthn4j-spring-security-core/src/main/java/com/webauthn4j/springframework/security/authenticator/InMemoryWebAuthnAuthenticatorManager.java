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
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public class InMemoryWebAuthnAuthenticatorManager implements WebAuthnAuthenticatorManager {

    private MultiValueMap<Object, WebAuthnAuthenticator> multiValueMap = new LinkedMultiValueMap<>();

    @Override
    public void updateCounter(byte[] credentialId, long counter) throws CredentialIdNotFoundException {
        WebAuthnAuthenticator webAuthnAuthenticator = this.loadAuthenticatorByCredentialId(credentialId);
        webAuthnAuthenticator.setCounter(counter);
    }

    @Override
    public WebAuthnAuthenticator loadAuthenticatorByCredentialId(byte[] credentialId) throws CredentialIdNotFoundException{
        return multiValueMap.values().stream().
                flatMap(Collection::stream)
                .filter(authenticator -> Arrays.equals(authenticator.getAttestedCredentialData().getCredentialId(), credentialId))
                .findFirst().orElseThrow(()-> new CredentialIdNotFoundException("credentialId not found."));
    }

    @Override
    public List<WebAuthnAuthenticator> loadAuthenticatorsByPrincipal(Object userPrincipal) {
        List<WebAuthnAuthenticator> list = multiValueMap.get(userPrincipal);
        if(list == null){
            throw new PrincipalNotFoundException("principal not found.");
        }
        return list;
    }

    @Override
    public void createAuthenticator(Object userPrincipal, WebAuthnAuthenticator webAuthnAuthenticator) {
        multiValueMap.add(userPrincipal, webAuthnAuthenticator);
    }

    @Override
    public void deleteAuthenticator(byte[] credentialId) {
        for (Map.Entry<Object, List<WebAuthnAuthenticator>> entry : multiValueMap.entrySet()){
            WebAuthnAuthenticator webAuthnAuthenticator = entry.getValue().stream()
                    .filter( item -> Arrays.equals(credentialId, item.getAttestedCredentialData().getCredentialId()))
                    .findFirst().orElse(null);
            if(webAuthnAuthenticator != null){
                multiValueMap.remove(entry.getKey(), webAuthnAuthenticator);
                break;
            }
        }
        throw new CredentialIdNotFoundException("credentialId not found.");
    }

    @Override
    public boolean authenticatorExists(byte[] credentialId) {
        return multiValueMap.values().stream().flatMap(Collection::stream).anyMatch( webAuthnAuthenticator -> Arrays.equals(credentialId, webAuthnAuthenticator.getAttestedCredentialData().getCredentialId()));
    }
}
