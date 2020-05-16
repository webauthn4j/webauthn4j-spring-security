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

package com.webauthn4j.springframework.security.webauthn.sample.app.security;

import com.webauthn4j.springframework.security.webauthn.sample.domain.component.UserManager;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import com.webauthn4j.springframework.security.fido.server.endpoint.UsernameNotFoundHandler;

import java.util.Collections;

public class SampleUsernameNotFoundHandler implements UsernameNotFoundHandler {

    private UserManager userManager;

    public SampleUsernameNotFoundHandler(UserManager userManager) {
        this.userManager = userManager;
    }

    @Override
    public void onUsernameNotFound(String loginUsername) {
        byte[] userHandle = new byte[0]; //TODO
        UserEntity userEntity = new UserEntity();
        userEntity.setUserHandle(userHandle);
        userEntity.setEmailAddress(loginUsername);
        userEntity.setLastName("dummy");
        userEntity.setFirstName("dummy");
        userEntity.setSingleFactorAuthenticationAllowed(false);
        userEntity.setPassword("dummy");
        userEntity.setGroups(Collections.emptyList());
        userEntity.setAuthorities(Collections.emptyList());
        userEntity.setAuthenticators(Collections.emptyList());
        userManager.createUser(userEntity);
    }
}
