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

package com.webauthn4j.springframework.security.options;

import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;

public class RpIdProviderImplTest {

    @Test
    public void getEffectiveRpId() {
        RpIdProviderImpl rpIdProvider = new RpIdProviderImpl();

        final String serverName = "example.com";
        final MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setServerPort(8080);
        mockHttpServletRequest.setScheme("https");
        mockHttpServletRequest.setServerName(serverName);

        try (MockedStatic<RequestContextHolder> requestContextHolderMockedStatic = Mockito.mockStatic(RequestContextHolder.class)) {
            requestContextHolderMockedStatic.when(RequestContextHolder::getRequestAttributes).thenReturn(new ServletRequestAttributes(mockHttpServletRequest));
            assertThat(rpIdProvider.provide()).isEqualTo("example.com");
            requestContextHolderMockedStatic.verify(RequestContextHolder::getRequestAttributes, times(1));
        }
    }

}