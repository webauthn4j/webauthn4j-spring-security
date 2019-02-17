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

package net.sharplab.springframework.security.webauthn.converter;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.response.attestation.AttestationObject;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class Base64StringToAttestationObjectConverterTest {

    private CborConverter cborConverter = new CborConverter();

    @Test
    public void convert_test() {
        AttestationObject expected = TestUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        String source = new AttestationObjectConverter(cborConverter).convertToString(expected);
        Base64StringToAttestationObjectConverter converter = new Base64StringToAttestationObjectConverter(cborConverter);
        AttestationObject result = converter.convert(source);
        assertThat(result).isEqualTo(expected);
    }
}
