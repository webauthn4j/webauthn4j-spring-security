package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

public class BadCredentialIdException extends AuthenticationException {
    public BadCredentialIdException(String message, Throwable cause) {
        super(message, cause);
    }

    public BadCredentialIdException(String message) {
        super(message);
    }
}
