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

package com.webauthn4j.springframework.security;

import com.webauthn4j.server.ServerProperty;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

public class WebAuthnAuthenticationParameters implements Serializable {

    private final ServerProperty serverProperty;
    private final boolean userVerificationRequired;
    private final boolean userPresenceRequired;
    private final List<String> expectedAuthenticationExtensionIds;

    public WebAuthnAuthenticationParameters(
            ServerProperty serverProperty,
            boolean userVerificationRequired,
            boolean userPresenceRequired,
            List<String> expectedAuthenticationExtensionIds) {
        this.serverProperty = serverProperty;
        this.userVerificationRequired = userVerificationRequired;
        this.userPresenceRequired = userPresenceRequired;
        this.expectedAuthenticationExtensionIds = expectedAuthenticationExtensionIds;
    }

    public ServerProperty getServerProperty() {
        return serverProperty;
    }

    public boolean isUserVerificationRequired() {
        return userVerificationRequired;
    }

    public boolean isUserPresenceRequired() {
        return userPresenceRequired;
    }

    public List<String> getExpectedAuthenticationExtensionIds() {
        return expectedAuthenticationExtensionIds;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnAuthenticationParameters that = (WebAuthnAuthenticationParameters) o;
        return userVerificationRequired == that.userVerificationRequired &&
                userPresenceRequired == that.userPresenceRequired &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(expectedAuthenticationExtensionIds, that.expectedAuthenticationExtensionIds);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverProperty, userVerificationRequired, userPresenceRequired, expectedAuthenticationExtensionIds);
    }
}
