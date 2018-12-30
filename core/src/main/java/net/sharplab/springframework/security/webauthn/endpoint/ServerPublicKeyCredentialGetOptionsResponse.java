package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.request.UserVerificationRequirement;
import com.webauthn4j.request.extension.client.AuthenticationExtensionsClientInputs;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

public class ServerPublicKeyCredentialGetOptionsResponse extends ServerResponseBase {
    private String challenge;
    private BigInteger timeout;
    private String rpId;
    private List<ServerPublicKeyCredentialDescriptor> allowCredentials;
    private UserVerificationRequirement userVerification;
    private AuthenticationExtensionsClientInputs extensions;

    public ServerPublicKeyCredentialGetOptionsResponse(
            String challenge,
            BigInteger timeout,
            String rpId,
            List<ServerPublicKeyCredentialDescriptor> allowCredentials,
            UserVerificationRequirement userVerification,
            AuthenticationExtensionsClientInputs extensions) {
        super();
        this.challenge = challenge;
        this.timeout = timeout;
        this.rpId = rpId;
        this.allowCredentials = allowCredentials;
        this.userVerification = userVerification;
        this.extensions = extensions;
    }

    public ServerPublicKeyCredentialGetOptionsResponse(String challenge) {
        super();
        this.challenge = challenge;
    }

    public ServerPublicKeyCredentialGetOptionsResponse() {
        super();
    }

    public String getChallenge() {
        return challenge;
    }

    public BigInteger getTimeout() {
        return timeout;
    }

    public String getRpId() {
        return rpId;
    }

    public List<ServerPublicKeyCredentialDescriptor> getAllowCredentials() {
        return allowCredentials;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    public AuthenticationExtensionsClientInputs getExtensions() {
        return extensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerPublicKeyCredentialGetOptionsResponse that = (ServerPublicKeyCredentialGetOptionsResponse) o;
        return Objects.equals(challenge, that.challenge) &&
                Objects.equals(timeout, that.timeout) &&
                Objects.equals(rpId, that.rpId) &&
                Objects.equals(allowCredentials, that.allowCredentials) &&
                userVerification == that.userVerification &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {

        return Objects.hash(challenge, timeout, rpId, allowCredentials, userVerification, extensions);
    }
}
