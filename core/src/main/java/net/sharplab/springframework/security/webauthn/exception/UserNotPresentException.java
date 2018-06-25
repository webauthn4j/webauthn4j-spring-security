package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if user is to be present but not present
 */
public class UserNotPresentException extends AuthenticationException {

    public UserNotPresentException(String message, Throwable cause) {
        super(message, cause);
    }

    public UserNotPresentException(String message) {
        super(message);
    }
}
