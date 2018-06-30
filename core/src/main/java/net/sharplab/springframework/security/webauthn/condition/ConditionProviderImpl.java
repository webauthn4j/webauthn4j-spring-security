/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.condition;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class ConditionProviderImpl implements ConditionProvider {

    //~ Instance fields
    // ================================================================================================
    private WebAuthnUserDetailsService userDetailsService;

    public ConditionProviderImpl(WebAuthnUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public Condition provide(String username, ServerProperty serverProperty) {
        Collection<? extends Authenticator> authenticators = userDetailsService.loadUserByUsername(username).getAuthenticators();
        List<Condition.Credential> credentials = new ArrayList<>();
        for (Authenticator authenticator : authenticators){
            byte[] credentialId = authenticator.getAttestedCredentialData().getCredentialId();
            credentials.add(new Condition.Credential(Base64UrlUtil.encodeToString(credentialId)));
        }
        String rpId = serverProperty.getRpId();
        String challenge = Base64UrlUtil.encodeToString(serverProperty.getChallenge().getValue());
        return new Condition(rpId, challenge, credentials);
    }

}
