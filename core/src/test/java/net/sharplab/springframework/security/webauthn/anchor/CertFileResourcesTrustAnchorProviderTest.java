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

package net.sharplab.springframework.security.webauthn.anchor;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class CertFileResourcesTrustAnchorProviderTest {


    @Test
    public void load_pemFile_test() {
        CertFileResourcesTrustAnchorProvider trustAnchorProvider = new CertFileResourcesTrustAnchorProvider();
        Resource resource = new ClassPathResource("certs/3tier-test-root-CA.pem");
        trustAnchorProvider.setPemFiles(Collections.singletonList(resource));
        Set<TrustAnchor> trustAnchors = trustAnchorProvider.loadTrustAnchors();
        assertThat(trustAnchors).hasSize(1);
    }

    @Test
    public void load_derFile_test() {
        CertFileResourcesTrustAnchorProvider trustAnchorProvider = new CertFileResourcesTrustAnchorProvider();
        Resource resource = new ClassPathResource("certs/3tier-test-root-CA.der");
        trustAnchorProvider.setPemFiles(Collections.singletonList(resource));
        Set<TrustAnchor> trustAnchors = trustAnchorProvider.loadTrustAnchors();
        assertThat(trustAnchors).hasSize(1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void afterPropertiesSet_test() {
        CertFileResourcesTrustAnchorProvider trustAnchorProvider = new CertFileResourcesTrustAnchorProvider();
        trustAnchorProvider.afterPropertiesSet();
    }
}
