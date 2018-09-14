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

package net.sharplab.springframework.security.webauthn.options;

import com.webauthn4j.client.challenge.Challenge;

import java.util.List;

public class Options {

    //~ Instance fields
    // ================================================================================================
    private RelyingParty relyingParty;
    private Challenge challenge;
    private List<PublicKeyCredentialParameters> pubKeyCredParams;
    private Integer timeout;
    private List<Credential> credentials;
    private Parameters parameters;

    public Options(RelyingParty relyingParty, Challenge challenge, List<PublicKeyCredentialParameters> pubKeyCredParams,
                   Integer timeout, List<Credential> credentials, Parameters parameters) {
        this.relyingParty = relyingParty;
        this.challenge = challenge;
        this.pubKeyCredParams = pubKeyCredParams;
        this.timeout = timeout;
        this.credentials = credentials;
        this.parameters = parameters;
    }

    public RelyingParty getRelyingParty() {
        return relyingParty;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public Integer getTimeout() {
        return timeout;
    }

    public List<Credential> getCredentials() {
        return credentials;
    }

    public Parameters getParameters() {
        return parameters;
    }

}
