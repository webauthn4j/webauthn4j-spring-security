package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.request.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.response.client.challenge.Challenge;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

public class AssertionOptions implements Serializable {

    private Challenge challenge;
    private BigInteger authenticationTimeout;
    private String rpId;
    private List<ServerPublicKeyCredentialDescriptor> credentials;
    private AuthenticationExtensionsClientInputs authenticationExtensions;
    private Parameters parameters;

    public AssertionOptions(
            Challenge challenge,
            BigInteger authenticationTimeout,
            String rpId,
            List<ServerPublicKeyCredentialDescriptor> credentials,
            AuthenticationExtensionsClientInputs authenticationExtensions,
            Parameters parameters) {
        this.challenge = challenge;
        this.authenticationTimeout = authenticationTimeout;
        this.rpId = rpId;
        this.credentials = credentials;
        this.authenticationExtensions = authenticationExtensions;
        this.parameters = parameters;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public BigInteger getAuthenticationTimeout() {
        return authenticationTimeout;
    }

    public String getRpId() {
        return rpId;
    }

    public List<ServerPublicKeyCredentialDescriptor> getCredentials() {
        return credentials;
    }

    public AuthenticationExtensionsClientInputs getAuthenticationExtensions() {
        return authenticationExtensions;
    }

    public Parameters getParameters() {
        return parameters;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AssertionOptions that = (AssertionOptions) o;
        return Objects.equals(challenge, that.challenge) &&
                Objects.equals(authenticationTimeout, that.authenticationTimeout) &&
                Objects.equals(rpId, that.rpId) &&
                Objects.equals(credentials, that.credentials) &&
                Objects.equals(authenticationExtensions, that.authenticationExtensions) &&
                Objects.equals(parameters, that.parameters);
    }

    @Override
    public int hashCode() {

        return Objects.hash(challenge, authenticationTimeout, rpId, credentials, authenticationExtensions, parameters);
    }
}
