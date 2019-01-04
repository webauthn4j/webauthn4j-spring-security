package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.client.challenge.DefaultChallenge;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

class ServerEndpointFilterUtil {

    private JsonConverter jsonConverter;
    private CborConverter cborConverter;

    ServerEndpointFilterUtil(Registry registry){
        this.jsonConverter = new JsonConverter(registry.getJsonMapper());
        this.cborConverter = new CborConverter(registry.getCborMapper());
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
        } else {
            errorResponse = new ErrorResponse("The server encountered an internal error");
            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
        String errorResponseText = jsonConverter.writeValueAsString(errorResponse);
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().print(errorResponseText);
        httpServletResponse.setStatus(statusCode);
    }

    Challenge encodeUsername(Challenge challenge, String username){
        UsernameEncordedChallengeEnvelope envelope = new UsernameEncordedChallengeEnvelope();
        envelope.setChallenge(challenge.getValue());
        envelope.setUsername(username);
        byte[] bytes = cborConverter.writeValueAsBytes(envelope);
        return new DefaultChallenge(bytes);
    }

    String decodeUsername(Challenge challenge){
        try{
            UsernameEncordedChallengeEnvelope envelope = cborConverter.readValue(challenge.getValue(), UsernameEncordedChallengeEnvelope.class);
            return envelope.getUsername();
        }
        catch (RuntimeException e){
            return null;
        }
    }

    static class UsernameEncordedChallengeEnvelope{
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
