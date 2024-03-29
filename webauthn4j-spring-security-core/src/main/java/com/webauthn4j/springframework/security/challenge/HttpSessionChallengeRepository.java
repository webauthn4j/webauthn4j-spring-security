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

package com.webauthn4j.springframework.security.challenge;

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.util.Assert;


/**
 * A {@link ChallengeRepository} implementation that stores data to HTTP session
 * <p>
 * Class design is based on {@link HttpSessionCsrfTokenRepository}
 */
public class HttpSessionChallengeRepository implements ChallengeRepository {

    // ~ Static fields/initializers
    // =====================================================================================

    private static final String DEFAULT_CHALLENGE_ATTR_NAME = HttpSessionChallengeRepository.class
            .getName().concat(".CHALLENGE");

    //~ Instance fields
    // ================================================================================================
    private String sessionAttributeName = DEFAULT_CHALLENGE_ATTR_NAME;

    // ~ Methods
    // ========================================================================================================

    @Override
    public Challenge generateChallenge() {
        return new DefaultChallenge();
    }

    @Override
    public void saveChallenge(Challenge challenge, HttpServletRequest request) {
        if (challenge == null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(this.sessionAttributeName);
            }
        } else {
            HttpSession session = request.getSession();
            session.setAttribute(this.sessionAttributeName, challenge);
        }
    }

    @Override
    public Challenge loadChallenge(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return (Challenge) session.getAttribute(this.sessionAttributeName);
    }

    /**
     * Sets the {@link HttpSession} attribute name that the {@link Challenge} is stored in
     *
     * @param sessionAttributeName the new attribute name to use
     */
    public void setSessionAttributeName(String sessionAttributeName) {
        Assert.hasLength(sessionAttributeName,
                "sessionAttributename cannot be null or empty");
        this.sessionAttributeName = sessionAttributeName;
    }

}
