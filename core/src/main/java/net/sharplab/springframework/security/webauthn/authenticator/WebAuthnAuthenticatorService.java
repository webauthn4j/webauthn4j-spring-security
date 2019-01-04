package net.sharplab.springframework.security.webauthn.authenticator;

import net.sharplab.springframework.security.webauthn.exception.CredentialIdNotFoundException;

public interface WebAuthnAuthenticatorService {

    /**
     * Updates Authenticator counter
     *
     * @param credentialId credentialId
     * @param counter      counter
     * @throws CredentialIdNotFoundException if the authenticator could not be found
     */
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    void updateCounter(byte[] credentialId, long counter) throws CredentialIdNotFoundException;

}
