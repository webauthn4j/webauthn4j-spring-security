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

import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.response.client.ClientDataType;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class Base64StringToCollectedClientDataConverterTest {

    private JsonConverter jsonConverter = new JsonConverter();

    @Test
    public void convert_test() {
        CollectedClientData expected = TestUtil.createClientData(ClientDataType.GET);
        String source = new CollectedClientDataConverter(jsonConverter).convertToBase64UrlString(expected);

        CollectedClientData result = new Base64StringToCollectedClientDataConverter(jsonConverter).convert(source);

        assertThat(result).isEqualTo(expected);
    }
}
