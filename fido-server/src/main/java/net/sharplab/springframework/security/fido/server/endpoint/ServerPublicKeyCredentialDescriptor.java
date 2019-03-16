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

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialType;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

public class ServerPublicKeyCredentialDescriptor implements Serializable {
    private PublicKeyCredentialType type;
    private String id;
    private List<AuthenticatorTransport> transports;

    public ServerPublicKeyCredentialDescriptor(PublicKeyCredentialType type, String id, List<AuthenticatorTransport> transports) {
        this.type = type;
        this.id = id;
        this.transports = transports;
    }

    public ServerPublicKeyCredentialDescriptor(String id) {
        this.type = PublicKeyCredentialType.PUBLIC_KEY;
        this.id = id;
        this.transports = null;
    }

    public ServerPublicKeyCredentialDescriptor() {
    }

    public PublicKeyCredentialType getType() {
        return type;
    }

    public String getId() {
        return id;
    }

    public List<AuthenticatorTransport> getTransports() {
        return transports;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerPublicKeyCredentialDescriptor that = (ServerPublicKeyCredentialDescriptor) o;
        return type == that.type &&
                Objects.equals(id, that.id) &&
                Objects.equals(transports, that.transports);
    }

    @Override
    public int hashCode() {

        return Objects.hash(type, id, transports);
    }
}
