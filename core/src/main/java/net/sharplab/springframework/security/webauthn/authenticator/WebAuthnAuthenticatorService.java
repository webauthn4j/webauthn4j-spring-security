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

package net.sharplab.springframework.security.webauthn.authenticator;

import net.sharplab.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Web Authentication specialized {@link UserDetailsService}
 */
public interface WebAuthnAuthenticatorService {

    /**
     * Locates the authenticator based on the credentialId.
     *
     * @param credentialId the credentialId identifying the authenticator whose data is required.
     * @return a fully populated authenticator record (never <code>null</code>)
     * @throws CredentialIdNotFoundException if the authenticator could not be found
     */
    WebAuthnAuthenticator loadWebAuthnAuthenticatorByCredentialId(byte[] credentialId);

}
