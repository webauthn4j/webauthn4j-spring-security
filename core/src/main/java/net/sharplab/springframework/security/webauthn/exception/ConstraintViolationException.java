package net.sharplab.springframework.security.webauthn.exception;

import com.webauthn4j.validator.exception.ValidationException;

/**
 * Thrown if the value violates constraints
 */
public class ConstraintViolationException extends ValidationException {

    public ConstraintViolationException(String message, Throwable cause) {
        super(message, cause);
    }

    public ConstraintViolationException(String message) {
        super(message);
    }
}
