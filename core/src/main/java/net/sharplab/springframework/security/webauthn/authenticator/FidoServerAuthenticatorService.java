package net.sharplab.springframework.security.webauthn.authenticator;


import com.webauthn4j.authenticator.Authenticator;

public interface FidoServerAuthenticatorService extends WebAuthnAuthenticatorService {

    void createAuthenticator(Authenticator authenticator);

    void addAuthenticatorToUser(byte[] credentialId, String username);

}
