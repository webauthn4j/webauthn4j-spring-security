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

package com.webauthn4j.springframework.security.endpoint;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.springframework.security.options.AssertionOptions;
import com.webauthn4j.springframework.security.options.AssertionOptionsProvider;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class AssertionOptionsEndpointFilterTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    @Test
    public void doFilter_test() throws IOException, ServletException {
        AssertionOptionsProvider optionsProvider = mock(AssertionOptionsProvider.class);
        AssertionOptions assertionOptions = new AssertionOptions(null, null, null, null, null,null);
        when(optionsProvider.getAssertionOptions(any(), any())).thenReturn(assertionOptions);
        AssertionOptionsEndpointFilter optionsEndpointFilter = new AssertionOptionsEndpointFilter(optionsProvider, objectConverter);
        AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
        optionsEndpointFilter.setTrustResolver(trustResolver);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(AssertionOptionsEndpointFilter.FILTER_URL);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        optionsEndpointFilter.doFilter(request, response, filterChain);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @Test
    public void doFilter_with_unmatched_url_test() throws IOException, ServletException {
        AssertionOptionsProvider optionsProvider = mock(AssertionOptionsProvider.class);
        AssertionOptionsEndpointFilter optionsEndpointFilter = new AssertionOptionsEndpointFilter(optionsProvider, objectConverter);
        AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
        optionsEndpointFilter.setTrustResolver(trustResolver);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/unmatched_url");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        optionsEndpointFilter.doFilter(request, response, filterChain);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @Test
    public void doFilter_with_error_test() throws IOException, ServletException {
        AssertionOptionsProvider optionsProvider = mock(AssertionOptionsProvider.class);
        doThrow(new RuntimeException()).when(optionsProvider).getAssertionOptions(any(), any());
        AssertionOptionsEndpointFilter optionsEndpointFilter = new AssertionOptionsEndpointFilter(optionsProvider, objectConverter);
        AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
        optionsEndpointFilter.setTrustResolver(trustResolver);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(AssertionOptionsEndpointFilter.FILTER_URL);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        optionsEndpointFilter.doFilter(request, response, filterChain);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
    }

}