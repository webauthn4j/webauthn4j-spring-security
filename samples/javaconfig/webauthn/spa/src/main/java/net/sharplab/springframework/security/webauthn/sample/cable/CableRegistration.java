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
import java.util.List;
import java.util.Objects;

public class CableRegistration implements Serializable {

    private List<Integer> version;
    private Integer maxVersion;
    private byte[] authenticatorPublicKey; //or publickey?

    public CableRegistration(List<Integer> version, Integer maxVersion, byte[] authenticatorPublicKey) {
        this.version = version;
        this.maxVersion = maxVersion;
        this.authenticatorPublicKey = authenticatorPublicKey;
    }

    public List<Integer> getVersion() {
        return version;
    }

    public Integer getMaxVersion() {
        return maxVersion;
    }

    public byte[] getAuthenticatorPublicKey() {
        return authenticatorPublicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CableRegistration that = (CableRegistration) o;
        return Objects.equals(version, that.version) &&
                Objects.equals(maxVersion, that.maxVersion) &&
                Arrays.equals(authenticatorPublicKey, that.authenticatorPublicKey);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(version, maxVersion);
        result = 31 * result + Arrays.hashCode(authenticatorPublicKey);
        return result;
    }
}
