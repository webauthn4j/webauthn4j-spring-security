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
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.options.RpIdProvider;
import com.webauthn4j.springframework.security.options.RpIdProviderImpl;
import com.webauthn4j.springframework.security.util.internal.ServletUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.Assert;

/**
 * {@inheritDoc}
 */
public class ServerPropertyProviderImpl implements ServerPropertyProvider {

    //~ Instance fields
    // ================================================================================================
    private String rpId;
    private RpIdProvider rpIdProvider;
    private RpIdProvider defaultRpIdProvider = new RpIdProviderImpl();
    private final ChallengeRepository challengeRepository;

    public ServerPropertyProviderImpl(RpIdProvider rpIdProvider, ChallengeRepository challengeRepository) {
        Assert.notNull(challengeRepository, "challengeRepository must not be null");

        this.rpIdProvider = rpIdProvider;
        this.challengeRepository = challengeRepository;
    }

    public ServerPropertyProviderImpl(ChallengeRepository challengeRepository){
        this(null, challengeRepository);
    }

    /**
     * {@inheritDoc}
     */
    public ServerProperty provide(HttpServletRequest request) {

        Origin origin = ServletUtil.getOrigin(request);
        String effectiveRpId = getRpId(request);
        Challenge challenge = challengeRepository.loadOrGenerateChallenge(request);

        return new ServerProperty(origin, effectiveRpId, challenge, null); // tokenBinding is not supported by Servlet API as of 4.0
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    String getRpId(HttpServletRequest request) {
        if(rpIdProvider != null){
            return rpIdProvider.provide(request);
        }
        else if(rpId != null){
            return rpId;
        }
        else {
            return defaultRpIdProvider.provide(request);
        }
    }

    public RpIdProvider getRpIdProvider() {
        return rpIdProvider;
    }

    public void setRpIdProvider(RpIdProvider rpIdProvider) {
        this.rpIdProvider = rpIdProvider;
    }
}
