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

package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.data.PublicKeyCredentialEntity;

import java.util.Objects;

public class ServerPublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {

    private String id;
    private String displayName;

    public ServerPublicKeyCredentialUserEntity(String id, String name, String displayName, String icon) {
        super(name, icon);
        this.id = id;
        this.displayName = displayName;
    }

    public ServerPublicKeyCredentialUserEntity(String id, String name, String displayName) {
        super(name);
        this.id = id;
        this.displayName = displayName;
    }

    public ServerPublicKeyCredentialUserEntity() {
    }

    public String getId() {
        return id;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerPublicKeyCredentialUserEntity that = (ServerPublicKeyCredentialUserEntity) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(displayName, that.displayName);
    }

    @Override
    public int hashCode() {

        return Objects.hash(id, displayName);
    }
}
