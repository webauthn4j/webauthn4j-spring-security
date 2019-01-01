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

package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.request.PublicKeyCredentialParameters;
import com.webauthn4j.response.client.challenge.Challenge;

import javax.servlet.http.HttpServletRequest;
import java.math.BigInteger;
import java.util.List;

public interface OptionsProvider {


    /**
     * provides AttestationOptions. If <code>username</code> is <code>null</code>, <code>user</code>, <code>credentials</code> are not populated.
     * @param request request
     * @param username username
     * @param challenge if null, new challenge is generated. Otherwise, specified challenge is used.
     * @return {@link Options} instance
     */
    AttestationOptions getAttestationOptions(HttpServletRequest request, String username, Challenge challenge);

    /**
     * provides AssertionOptions. If <code>username</code> is <code>null</code>, <code>credentials</code> are not populated.
     * @param request request
     * @param username username
     * @param challenge if null, new challenge is generated. Otherwise, specified challenge is used.
     * @return {@link Options} instance
     */
    AssertionOptions getAssertionOptions(HttpServletRequest request, String username, Challenge challenge);

    /**
     * returns effective rpId based on request origin and configured <code>rpId</code>.
     * @param request request
     * @return effective rpId
     */
    String getEffectiveRpId(HttpServletRequest request);

    /**
     * returns configured rpId
     * @return rpId
     */
    String getRpId();

    /**
     * configures rpId
     */
    void setRpId(String rpId);

    /**
     * returns rpName
     * @return rpName
     */
    String getRpName();

    /**
     * configures rpName
     * @param rpName rpName
     */
    void setRpName(String rpName);

    /**
     * returns rpIcon
     * @return rpIcon
     */
    String getRpIcon();

    void setRpIcon(String rpIcon);

    /**
     * returns {@link PublicKeyCredentialParameters} list
     * @return {@link PublicKeyCredentialParameters} list
     */
    List<PublicKeyCredentialParameters> getPubKeyCredParams();

    /**
     * configures pubKeyCredParams
     * @param pubKeyCredParams {@link PublicKeyCredentialParameters} list
     */
    void setPubKeyCredParams(List<PublicKeyCredentialParameters> pubKeyCredParams);

    BigInteger getRegistrationTimeout();
    void setRegistrationTimeout(BigInteger registrationTimeout);
    BigInteger getAuthenticationTimeout();
    void setAuthenticationTimeout(BigInteger authenticationTimeout);

    String getUsernameParameter();

    void setUsernameParameter(String usernameParameter);

    String getPasswordParameter();

    void setPasswordParameter(String passwordParameter);

    String getCredentialIdParameter();

    void setCredentialIdParameter(String credentialIdParameter);

    String getClientDataJSONParameter();

    void setClientDataJSONParameter(String clientDataJSONParameter);

    String getAuthenticatorDataParameter();

    void setAuthenticatorDataParameter(String authenticatorDataParameter);

    String getSignatureParameter();

    void setSignatureParameter(String signatureParameter);

    String getClientExtensionsJSONParameter();

    void setClientExtensionsJSONParameter(String clientExtensionsJSONParameter);

}
