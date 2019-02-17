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

package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.client.challenge.DefaultChallenge;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

class ServerEndpointFilterUtil {

    private JsonConverter jsonConverter;
    private CborConverter cborConverter;

    ServerEndpointFilterUtil(JsonConverter jsonConverter) {
        this.jsonConverter = jsonConverter;
        this.cborConverter = jsonConverter.getCborConverter();
    }

    void writeResponse(HttpServletResponse httpServletResponse, ServerResponse response) throws IOException {
        String responseText = jsonConverter.writeValueAsString(response);
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().print(responseText);
    }

    void writeErrorResponse(HttpServletResponse httpServletResponse, RuntimeException e) throws IOException {
        ErrorResponse errorResponse;
        int statusCode;
        if (e instanceof InsufficientAuthenticationException) {
            errorResponse = new ErrorResponse("Anonymous access is prohibited");
            statusCode = HttpServletResponse.SC_FORBIDDEN;
        }
        else if(e instanceof AuthenticationException || e instanceof IllegalArgumentException){
            errorResponse = new ErrorResponse("Authentication failed");
            statusCode = HttpServletResponse.SC_FORBIDDEN;
        }
        else {
            errorResponse = new ErrorResponse("The server encountered an internal error");
            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
        String errorResponseText = jsonConverter.writeValueAsString(errorResponse);
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().print(errorResponseText);
        httpServletResponse.setStatus(statusCode);
    }

    Challenge encodeUsername(Challenge challenge, String username) {
        UsernameEncordedChallengeEnvelope envelope = new UsernameEncordedChallengeEnvelope();
        envelope.setChallenge(challenge.getValue());
        envelope.setUsername(username);
        byte[] bytes = cborConverter.writeValueAsBytes(envelope);
        return new DefaultChallenge(bytes);
    }

    String decodeUsername(Challenge challenge) {
        try {
            UsernameEncordedChallengeEnvelope envelope = cborConverter.readValue(challenge.getValue(), UsernameEncordedChallengeEnvelope.class);
            return envelope.getUsername();
        } catch (RuntimeException e) {
            return null;
        }
    }

    static class UsernameEncordedChallengeEnvelope {
        private String username;
        private byte[] challenge;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public byte[] getChallenge() {
            return challenge;
        }

        public void setChallenge(byte[] challenge) {
            this.challenge = challenge;
        }
    }

}
