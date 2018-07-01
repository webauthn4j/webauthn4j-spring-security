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

import java.util.List;

public class Condition {

    //~ Instance fields
    // ================================================================================================
    private String rpId;
    private String challenge;
    private List<Credential> credentials;

    public Condition(String rpId, String challenge, List<Credential> credentials) {
        this.rpId = rpId;
        this.challenge = challenge;
        this.credentials = credentials;
    }

    public String getRpId() {
        return rpId;
    }

    public String getChallenge() {
        return challenge;
    }

    public List<Credential> getCredentials() {
        return credentials;
    }

    public static class Credential {

        private String id;

        public Credential(String id) {
            this.id = id;
        }

        public String getId() {
            return id;
        }

    }
}
