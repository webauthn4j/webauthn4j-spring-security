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

public interface WebAuthnAuthenticatorManager extends WebAuthnAuthenticatorService {

    /**
     * Create a new user with the supplied details.
     * @param webAuthnAuthenticator authenticator
     */
    void createAuthenticator(WebAuthnAuthenticator webAuthnAuthenticator);

    /**
     * Remove the authenticator with the given credentialId
     * @param credentialId credentialId
     */
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    void deleteAuthenticator(byte[] credentialId) throws CredentialIdNotFoundException;

    /**
     * Check if a authenticator with the supplied credentialId
     * @param credentialId credentialId
     * @return true if a authenticator with the supplied credentialId exists
     */
    boolean authenticatorExists(byte[] credentialId);

}
