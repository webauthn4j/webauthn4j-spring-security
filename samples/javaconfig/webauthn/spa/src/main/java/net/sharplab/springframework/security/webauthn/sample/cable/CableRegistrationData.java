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

import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.ECUtil;

import java.io.Serializable;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class CableRegistrationData implements Serializable {

    private List<Long> versions;
    private byte[] rpPublicKey;

    public CableRegistrationData(ECPublicKey rpPublicKey) {
        this(ECUtil.createUncompressedPublicKey(rpPublicKey));
    }

    public CableRegistrationData(byte[] rpPublicKey) {
        this(Collections.singletonList(1L), rpPublicKey);
    }

    public CableRegistrationData(List<Long> versions, byte[] rpPublicKey) {
        this.versions = Collections.unmodifiableList(versions);
        this.rpPublicKey = rpPublicKey;
    }

    public List<Long> getVersions() {
        return versions;
    }

    public byte[] getRpPublicKey() {
        return ArrayUtil.clone(rpPublicKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CableRegistrationData that = (CableRegistrationData) o;
        return Objects.equals(versions, that.versions) &&
                Arrays.equals(rpPublicKey, that.rpPublicKey);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(versions);
        result = 31 * result + Arrays.hashCode(rpPublicKey);
        return result;
    }
}
