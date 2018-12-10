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

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import net.sharplab.springframework.security.webauthn.util.ServletUtil;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class OptionsProviderImpl implements OptionsProvider {

    //~ Instance fields
    // ================================================================================================
    private String rpId = null;
    private String rpName = null;
    private List<PublicKeyCredentialParameters> publicKeyCredParams = new ArrayList<>();
    private Integer timeout = null;

    private String usernameParameter;
    private String passwordParameter;
    private String credentialIdParameter;
    private String clientDataParameter;
    private String authenticatorDataParameter;
    private String signatureParameter;
    private String clientExtensionsJSONParameter;

    private WebAuthnUserDetailsService userDetailsService;
    private ChallengeRepository challengeRepository;

    public OptionsProviderImpl(WebAuthnUserDetailsService userDetailsService, ChallengeRepository challengeRepository) {
        this.userDetailsService = userDetailsService;
        this.challengeRepository = challengeRepository;
    }

    public Options provide(HttpServletRequest request, String username) {
        Collection<? extends Authenticator> authenticators;
        if(username == null){
            authenticators = Collections.emptyList();
        }
        else{
            authenticators = userDetailsService.loadUserByUsername(username).getAuthenticators();
        }
        List<Credential> credentials = new ArrayList<>();
        for (Authenticator authenticator : authenticators) {
            byte[] credentialId = authenticator.getAttestedCredentialData().getCredentialId();
            credentials.add(new Credential(PublicKeyCredentialType.PUBLIC_KEY, Base64UrlUtil.encodeToString(credentialId)));
        }

        RelyingParty relyingParty = new RelyingParty(getEffectiveRpId(request), rpName);
        Challenge challenge = challengeRepository.loadOrGenerateChallenge(request);
        Parameters parameters = new Parameters(usernameParameter, passwordParameter, credentialIdParameter,
                clientDataParameter, authenticatorDataParameter, signatureParameter, clientExtensionsJSONParameter);

        return new Options(relyingParty, challenge, publicKeyCredParams, timeout, credentials, parameters);
    }

    public String getEffectiveRpId(HttpServletRequest request){
        String effectiveRpId;
        if (this.rpId != null) {
            effectiveRpId = this.rpId;
        }
        else {
            Origin origin = ServletUtil.getOrigin(request);
            effectiveRpId = origin.getHost();
        }
        return effectiveRpId;
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public String getRpName() {
        return rpName;
    }

    public void setRpName(String rpName) {
        this.rpName = rpName;
    }

    public List<PublicKeyCredentialParameters> getPublicKeyCredParams() {
        return publicKeyCredParams;
    }

    public void setPublicKeyCredParams(List<PublicKeyCredentialParameters> publicKeyCredParams) {
        this.publicKeyCredParams = publicKeyCredParams;
    }

    public Integer getTimeout() {
        return timeout;
    }

    public void setTimeout(Integer timeout) {
        this.timeout = timeout;
    }

    public String getUsernameParameter() {
        return usernameParameter;
    }

    public void setUsernameParameter(String usernameParameter) {
        this.usernameParameter = usernameParameter;
    }

    public String getPasswordParameter() {
        return passwordParameter;
    }

    public void setPasswordParameter(String passwordParameter) {
        this.passwordParameter = passwordParameter;
    }

    public String getCredentialIdParameter() {
        return credentialIdParameter;
    }

    public void setCredentialIdParameter(String credentialIdParameter) {
        this.credentialIdParameter = credentialIdParameter;
    }

    public String getClientDataParameter() {
        return clientDataParameter;
    }

    public void setClientDataParameter(String clientDataParameter) {
        this.clientDataParameter = clientDataParameter;
    }

    public String getAuthenticatorDataParameter() {
        return authenticatorDataParameter;
    }

    public void setAuthenticatorDataParameter(String authenticatorDataParameter) {
        this.authenticatorDataParameter = authenticatorDataParameter;
    }

    public String getSignatureParameter() {
        return signatureParameter;
    }

    public void setSignatureParameter(String signatureParameter) {
        this.signatureParameter = signatureParameter;
    }

    public String getClientExtensionsJSONParameter() {
        return clientExtensionsJSONParameter;
    }

    public void setClientExtensionsJSONParameter(String clientExtensionsJSONParameter) {
        this.clientExtensionsJSONParameter = clientExtensionsJSONParameter;
    }

}
