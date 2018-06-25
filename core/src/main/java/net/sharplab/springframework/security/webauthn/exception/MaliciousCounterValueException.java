package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if the counter value is lower than expected value
 */
public class MaliciousCounterValueException extends AuthenticationException {

    public MaliciousCounterValueException(String message, Throwable cause) {
        super(message, cause);
    }

    public MaliciousCounterValueException(String message) {
        super(message);
    }

}