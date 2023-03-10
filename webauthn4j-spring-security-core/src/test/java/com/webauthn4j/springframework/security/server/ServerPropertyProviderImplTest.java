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

package com.webauthn4j.springframework.security.server;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.options.RpIdProvider;
import com.webauthn4j.springframework.security.options.RpIdProviderImpl;
import com.webauthn4j.springframework.security.util.internal.ServletUtil;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class ServerPropertyProviderImplTest {

    private final ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
    private final RpIdProvider rpIdProvider = mock(RpIdProvider.class);
    private final ServerPropertyProviderImpl target = new ServerPropertyProviderImpl(rpIdProvider, challengeRepository);

    @Test
    public void provide_test() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        final String scheme = "https";
        final String serverName = "origin.example.com";
        final String rpId = "rpid.example.com";
        final String originURL = scheme + "://" + serverName;
        request.setScheme(scheme);
        request.setServerName(serverName);
        request.setServerPort(443);
        Challenge mockChallenge = new DefaultChallenge();
        when(challengeRepository.loadOrGenerateChallenge(request)).thenReturn(mockChallenge);
        when(rpIdProvider.provide()).thenReturn(rpId);
        try (MockedStatic<ServletUtil> servletUtil = Mockito.mockStatic(ServletUtil.class)) {
            servletUtil.when(ServletUtil::getOrigin).thenReturn(new Origin(originURL));
            ServerProperty serverProperty = target.provide(request);

            assertThat(serverProperty.getRpId()).isEqualTo(rpId);
            assertThat(serverProperty.getOrigins()).containsExactly(new Origin(originURL));
            assertThat(serverProperty.getChallenge()).isEqualTo(mockChallenge);
            servletUtil.verify(ServletUtil::getOrigin, times(1));
        }
    }

    @Test
    public void getRpId_without_rpId_and_rpIdProvider_set(){
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("origin.example.com");
        request.setServerPort(443);
        Challenge mockChallenge = new DefaultChallenge();
        when(challengeRepository.loadOrGenerateChallenge(request)).thenReturn(mockChallenge);
        ServerPropertyProviderImpl serverPropertyProviderImpl = new ServerPropertyProviderImpl(() ->"origin.example.com", challengeRepository);
        assertThat(serverPropertyProviderImpl.getEffectiveRpId()).isEqualTo("origin.example.com");
    }

    @Test
    public void getRpId_with_rpId_set(){
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("origin.example.com");
        request.setServerPort(443);
        Challenge mockChallenge = new DefaultChallenge();
        when(challengeRepository.loadOrGenerateChallenge(request)).thenReturn(mockChallenge);
        ServerPropertyProviderImpl serverPropertyProviderImpl = new ServerPropertyProviderImpl(() ->"origin.example.com", challengeRepository);
        serverPropertyProviderImpl.setRpId("example.com");
        assertThat(serverPropertyProviderImpl.getRpId()).isEqualTo("example.com");
    }

    @Test
    public void getRpId_with_rpIdProvider_set(){
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("origin.example.com");
        request.setServerPort(443);
        Challenge mockChallenge = new DefaultChallenge();
        when(challengeRepository.loadOrGenerateChallenge(request)).thenReturn(mockChallenge);
        ServerPropertyProviderImpl serverPropertyProviderImpl = new ServerPropertyProviderImpl(challengeRepository);
        serverPropertyProviderImpl.setRpIdProvider(() -> "example.com");
        assertThat(serverPropertyProviderImpl.getEffectiveRpId()).isEqualTo("example.com");
    }

    @Test
    public void getter_setter_test(){
        RpIdProvider rpIdProvider = new RpIdProviderImpl();
        target.setRpId("example.com");
        assertThat(target.getRpId()).isEqualTo("example.com");
        target.setRpIdProvider(rpIdProvider);
        assertThat(target.getRpIdProvider()).isEqualTo(rpIdProvider);
    }



}
