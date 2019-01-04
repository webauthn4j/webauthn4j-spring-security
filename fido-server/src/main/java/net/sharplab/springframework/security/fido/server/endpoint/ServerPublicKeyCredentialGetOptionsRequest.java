package net.sharplab.springframework.security.fido.server.endpoint;

import com.webauthn4j.request.UserVerificationRequirement;

import java.util.Objects;

public class ServerPublicKeyCredentialGetOptionsRequest implements ServerRequest {
    private String username;
    private UserVerificationRequirement userVerification;

    public ServerPublicKeyCredentialGetOptionsRequest(String username, UserVerificationRequirement userVerification) {
        this.username = username;
        this.userVerification = userVerification;
    }

    public ServerPublicKeyCredentialGetOptionsRequest(String username) {
        this.username = username;
        this.userVerification = UserVerificationRequirement.PREFERRED;
    }

    public ServerPublicKeyCredentialGetOptionsRequest(){
        this.userVerification = UserVerificationRequirement.PREFERRED;
    }

    public String getUsername() {
        return username;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerPublicKeyCredentialGetOptionsRequest that = (ServerPublicKeyCredentialGetOptionsRequest) o;
        return Objects.equals(username, that.username) &&
                userVerification == that.userVerification;
    }

    @Override
    public int hashCode() {

        return Objects.hash(username, userVerification);
    }
}
