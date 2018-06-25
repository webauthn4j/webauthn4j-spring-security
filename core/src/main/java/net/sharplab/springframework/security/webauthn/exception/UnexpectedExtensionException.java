package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

public class UnexpectedExtensionException extends AuthenticationException {
    public UnexpectedExtensionException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public UnexpectedExtensionException(String msg) {
        super(msg);
    }
}
