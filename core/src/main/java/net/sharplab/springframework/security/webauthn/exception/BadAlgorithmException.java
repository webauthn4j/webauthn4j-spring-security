package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if bad algorithm is specified
 */
public class BadAlgorithmException extends AuthenticationException {

    public BadAlgorithmException(String message, Throwable cause) {
        super(message, cause);
    }

    public BadAlgorithmException(String message) {
        super(message);
    }
}
