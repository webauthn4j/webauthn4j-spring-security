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

import com.webauthn4j.springframework.security.fido.server.endpoint.UsernameNotFoundHandler;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.UserDetailsManager;

import java.util.Collections;

public class SampleUsernameNotFoundHandler implements UsernameNotFoundHandler {

    private final UserDetailsManager userDetailsManager;

    public SampleUsernameNotFoundHandler(UserDetailsManager userDetailsManager) {
        this.userDetailsManager = userDetailsManager;
    }

    @Override
    public void onUsernameNotFound(String loginUsername) {
        User user = new User(loginUsername, "dummy", Collections.emptyList());
        userDetailsManager.createUser(user);
    }
}
