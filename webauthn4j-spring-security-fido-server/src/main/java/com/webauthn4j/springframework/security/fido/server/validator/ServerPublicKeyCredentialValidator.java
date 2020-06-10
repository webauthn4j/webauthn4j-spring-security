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

package com.webauthn4j.springframework.security.fido.server.validator;

import com.webauthn4j.springframework.security.fido.server.endpoint.ServerAuthenticatorResponse;
import com.webauthn4j.springframework.security.fido.server.endpoint.ServerPublicKeyCredential;
import com.webauthn4j.springframework.security.fido.server.util.BeanAssertUtil;
import com.webauthn4j.springframework.security.exception.BadCredentialIdException;
import com.webauthn4j.util.Base64UrlUtil;

public class ServerPublicKeyCredentialValidator<T extends ServerAuthenticatorResponse> {

    public void validate(ServerPublicKeyCredential<T> serverPublicKeyCredential) {

        BeanAssertUtil.validate(serverPublicKeyCredential);

        if (!serverPublicKeyCredential.getId().equals(serverPublicKeyCredential.getRawId())) {
            throw new BadCredentialIdException("id and rawId doesn't match");
        }

        try {
            Base64UrlUtil.decode(serverPublicKeyCredential.getId());
        } catch (IllegalArgumentException e) {
            throw new BadCredentialIdException("id cannot be parsed as base64url", e);
        }
    }
}
