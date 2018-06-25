package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if bad attestation statement is specified
 */
public class BadAttestationStatementException extends AuthenticationException {

    public BadAttestationStatementException(String message, Throwable cause) {
        super(message, cause);
    }

    public BadAttestationStatementException(String message) {
        super(message);
    }
}
