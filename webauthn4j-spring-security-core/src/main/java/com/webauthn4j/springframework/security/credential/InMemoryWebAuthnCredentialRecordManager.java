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

package com.webauthn4j.springframework.security.credential;

import com.webauthn4j.springframework.security.exception.CredentialIdNotFoundException;
import com.webauthn4j.springframework.security.exception.PrincipalNotFoundException;
import com.webauthn4j.util.Base64UrlUtil;

import java.util.*;

public class InMemoryWebAuthnCredentialRecordManager implements WebAuthnCredentialRecordManager {

    private Map<Object, Map<String, WebAuthnCredentialRecord>> map = new HashMap<>();

    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    @Override
    public void updateCounter(byte[] credentialId, long counter) throws CredentialIdNotFoundException {
        WebAuthnCredentialRecord webAuthnCredentialRecord = this.loadCredentialRecordByCredentialId(credentialId);
        webAuthnCredentialRecord.setCounter(counter);
    }

    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    @Override
    public WebAuthnCredentialRecord loadCredentialRecordByCredentialId(byte[] credentialId) throws CredentialIdNotFoundException{
        return map.values().stream().
                map(innerMap ->
                        innerMap.get(Base64UrlUtil.encodeToString(credentialId))
                ).filter(Objects::nonNull)
                .findFirst().orElseThrow(()-> new CredentialIdNotFoundException("credentialId not found."));
    }

    @Override
    public List<WebAuthnCredentialRecord> loadCredentialRecordsByUserPrincipal(Object userPrincipal) {
        Map<String, WebAuthnCredentialRecord> innerMap = map.get(userPrincipal);
        if(innerMap == null || innerMap.isEmpty()){
            throw new PrincipalNotFoundException("principal not found.");
        }
        return Collections.unmodifiableList(new ArrayList<>(innerMap.values()));
    }

    @Override
    public void createCredentialRecord(WebAuthnCredentialRecord webAuthnCredentialRecord) {
        Object userPrincipal = webAuthnCredentialRecord.getUserPrincipal();
        if(!map.containsKey(userPrincipal)){
            map.put(userPrincipal, new HashMap<>());
        }
        map.get(userPrincipal).put(Base64UrlUtil.encodeToString(webAuthnCredentialRecord.getAttestedCredentialData().getCredentialId()), webAuthnCredentialRecord);
    }

    @Override
    public void deleteCredentialRecord(byte[] credentialId) {
        for (Map.Entry<Object, Map<String, WebAuthnCredentialRecord>> entry : map.entrySet()){
            WebAuthnCredentialRecord webAuthnCredentialRecord = entry.getValue().get(Base64UrlUtil.encodeToString(credentialId));
            if(webAuthnCredentialRecord != null){
                entry.getValue().remove(Base64UrlUtil.encodeToString(credentialId));
                return;
            }
        }
        throw new CredentialIdNotFoundException("credentialId not found.");
    }

    @Override
    public boolean credentialRecordExists(byte[] credentialId) {
        return map.values().stream().anyMatch(innerMap -> innerMap.get(Base64UrlUtil.encodeToString(credentialId)) != null);
    }
}
