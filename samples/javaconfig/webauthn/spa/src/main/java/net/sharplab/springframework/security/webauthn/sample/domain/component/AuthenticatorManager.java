package net.sharplab.springframework.security.webauthn.sample.domain.component;

import net.sharplab.springframework.security.webauthn.authenticator.FidoServerAuthenticatorService;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;

public interface AuthenticatorManager extends WebAuthnAuthenticatorService, FidoServerAuthenticatorService {
}
