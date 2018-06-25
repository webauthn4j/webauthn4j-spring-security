package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

public class TokenBindingException extends AuthenticationException {
    public TokenBindingException(String message, Throwable cause) {
        super(message, cause);
    }

    public TokenBindingException(String message) {
        super(message);
    }
}
