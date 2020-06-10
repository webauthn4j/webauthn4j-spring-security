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

package com.webauthn4j.springframework.security.anchor;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CertFileResourcesTrustAnchorsProviderTest {


    @Test
    public void loadTrustAnchors_with_pemFile_test() {
        CertFileResourcesTrustAnchorsProvider trustAnchorProvider = new CertFileResourcesTrustAnchorsProvider();
        Resource resource = new ClassPathResource("certs/3tier-test-root-CA.pem");
        trustAnchorProvider.setCertificates(Collections.singletonList(resource));
        Map<AAGUID, Set<TrustAnchor>> trustAnchors = trustAnchorProvider.loadTrustAnchors();
        assertThat(trustAnchors).hasSize(1);
    }

    @Test
    public void loadTrustAnchors_with_derFile_test() {
        CertFileResourcesTrustAnchorsProvider trustAnchorProvider = new CertFileResourcesTrustAnchorsProvider();
        Resource resource = new ClassPathResource("certs/3tier-test-root-CA.der");
        trustAnchorProvider.setCertificates(Collections.singletonList(resource));
        Map<AAGUID, Set<TrustAnchor>> trustAnchors = trustAnchorProvider.loadTrustAnchors();
        assertThat(trustAnchors).hasSize(1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void afterPropertiesSet_test() {
        CertFileResourcesTrustAnchorsProvider trustAnchorProvider = new CertFileResourcesTrustAnchorsProvider();
        trustAnchorProvider.afterPropertiesSet();
    }

    @Test(expected = UncheckedIOException.class)
    public void loadTrustAnchor_test() throws IOException {
        CertFileResourcesTrustAnchorsProvider trustAnchorProvider = new CertFileResourcesTrustAnchorsProvider();
        Resource resource = mock(Resource.class);
        when(resource.getInputStream()).thenThrow(IOException.class);
        trustAnchorProvider.loadTrustAnchor(resource);
    }
}
