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

package com.webauthn4j.springframework.security.fido.server.util;

import com.webauthn4j.springframework.security.exception.ConstraintViolationException;
import com.webauthn4j.springframework.security.fido.server.endpoint.ServerAuthenticatorResponse;
import com.webauthn4j.springframework.security.fido.server.endpoint.ServerPublicKeyCredential;

public class BeanAssertUtil {

    private BeanAssertUtil() {
    }

    public static <T extends ServerAuthenticatorResponse> void validate(ServerPublicKeyCredential<T> serverPublicKeyCredential) {

        if (serverPublicKeyCredential == null) {
            throw new ConstraintViolationException("serverPublicKeyCredential must not be null");
        }
        if (serverPublicKeyCredential.getId() == null) {
            throw new ConstraintViolationException("id must not be null");
        }
        if (serverPublicKeyCredential.getRawId() == null) {
            throw new ConstraintViolationException("rawId must not be null");
        }
        if (serverPublicKeyCredential.getType() == null) {
            throw new ConstraintViolationException("type must not be null");
        }
        if (serverPublicKeyCredential.getResponse() == null) {
            throw new ConstraintViolationException("response must not be null");
        }
    }
}
