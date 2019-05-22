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

package net.sharplab.springframework.security.webauthn.sample.cable;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

public class CableAuthenticationData implements Serializable {

    private Long version;
    private byte[] clientEid;
    private byte[] authenticatorEid;
    private byte[] sessionPreKey;

    public CableAuthenticationData(Long version, byte[] clientEid, byte[] authenticatorEid, byte[] sessionPreKey) {
        this.version = version;
        this.clientEid = clientEid;
        this.authenticatorEid = authenticatorEid;
        this.sessionPreKey = sessionPreKey;
    }

    public Long getVersion() {
        return version;
    }

    public byte[] getClientEid() {
        return clientEid;
    }

    public byte[] getAuthenticatorEid() {
        return authenticatorEid;
    }

    public byte[] getSessionPreKey() {
        return sessionPreKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CableAuthenticationData that = (CableAuthenticationData) o;
        return Objects.equals(version, that.version) &&
                Arrays.equals(clientEid, that.clientEid) &&
                Arrays.equals(authenticatorEid, that.authenticatorEid) &&
                Arrays.equals(sessionPreKey, that.sessionPreKey);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(version);
        result = 31 * result + Arrays.hashCode(clientEid);
        result = 31 * result + Arrays.hashCode(authenticatorEid);
        result = 31 * result + Arrays.hashCode(sessionPreKey);
        return result;
    }
}
