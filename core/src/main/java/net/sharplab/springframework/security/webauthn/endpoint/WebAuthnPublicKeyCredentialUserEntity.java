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

package net.sharplab.springframework.security.webauthn.endpoint;

import java.io.Serializable;
import java.util.Objects;

public class WebAuthnPublicKeyCredentialUserEntity implements Serializable {

    private String userHandle;
    private String username;

    public WebAuthnPublicKeyCredentialUserEntity(String userHandle, String username) {
        this.userHandle = userHandle;
        this.username = username;
    }

    public WebAuthnPublicKeyCredentialUserEntity() {
    }

    public String getUserHandle() {
        return userHandle;
    }

    public String getUsername() {
        return username;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnPublicKeyCredentialUserEntity that = (WebAuthnPublicKeyCredentialUserEntity) o;
        return Objects.equals(userHandle, that.userHandle) &&
                Objects.equals(username, that.username);
    }

    @Override
    public int hashCode() {

        return Objects.hash(userHandle, username);
    }
}
