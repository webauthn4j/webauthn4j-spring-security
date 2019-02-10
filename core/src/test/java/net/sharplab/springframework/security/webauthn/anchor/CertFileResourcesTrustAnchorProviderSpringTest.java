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

import com.webauthn4j.response.attestation.authenticator.AAGUID;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.cert.CertificateEncodingException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
public class CertFileResourcesTrustAnchorProviderSpringTest {

    @Autowired
    private CertFileResourcesTrustAnchorProvider target;

    @Configuration
    public static class config{

        @Bean
        public CertFileResourcesTrustAnchorProvider certFileResourcesTrustAnchorProvider() throws CertificateEncodingException {
            Resource x509Resource = new ByteArrayResource(TestUtil.load2tierTestRootCACertificate().getEncoded());
            return new CertFileResourcesTrustAnchorProvider(Collections.singletonList(x509Resource));
        }
    }

    @Test
    public void loadTrustAnchors_test(){
        assertThat(target.loadTrustAnchors().get(AAGUID.NULL)).isNotNull();
    }

    @Test
    public void getCertificates_test(){
        assertThat(target.getCertificates()).isNotNull();
    }

}