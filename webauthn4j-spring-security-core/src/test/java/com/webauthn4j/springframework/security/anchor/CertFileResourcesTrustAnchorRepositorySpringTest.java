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
import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.security.cert.CertificateEncodingException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;


@ExtendWith(SpringExtension.class)
public class CertFileResourcesTrustAnchorRepositorySpringTest {

    @Autowired
    private CertFileResourcesTrustAnchorRepository target;

    @Test
    public void find_test() {
        assertThat(target.find(AAGUID.NULL)).isNotNull();
    }

    @Test
    public void getCertificates_test() {
        assertThat(target.getCertificates()).isNotNull();
    }

    @Configuration
    public static class config {

        @Bean
        public CertFileResourcesTrustAnchorRepository certFileResourcesTrustAnchorRepository() throws CertificateEncodingException {
            Resource x509Resource = new ByteArrayResource(TestAttestationUtil.load2tierTestAuthenticatorAttestationCertificate().getEncoded());
            return new CertFileResourcesTrustAnchorRepository(Collections.singletonList(x509Resource));
        }
    }

}