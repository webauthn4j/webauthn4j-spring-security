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

package com.webauthn4j.springframework.security.util;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.springframework.security.util.internal.ServletUtil;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

public class ServletUtilTest {

    @Test
    public void shouldGetOriginFromHttpServletRequest() {
        final String requestScheme = "https";
        final String requestServerName = "webauthn4j.spring.security";
        final Integer requestServerPort = 8090;

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme(requestScheme);
        request.setServerName(requestServerName);
        request.setServerPort(requestServerPort);

        final Origin origin = ServletUtil.getOrigin(request);

        assertThat(origin.getHost()).isEqualTo(requestServerName);
        assertThat(origin.getScheme()).isEqualTo(requestScheme);
        assertThat(origin.getPort()).isEqualTo(requestServerPort);
        assertThat(origin.getSchemeSpecificPart()).isEqualTo(String.format("//%s:%s", requestServerName, requestServerPort));
    }

}
