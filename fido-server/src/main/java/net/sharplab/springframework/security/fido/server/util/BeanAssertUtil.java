package net.sharplab.springframework.security.fido.server.util;

import net.sharplab.springframework.security.fido.server.endpoint.ServerPublicKeyCredential;
import net.sharplab.springframework.security.webauthn.exception.ConstraintViolationException;

public class BeanAssertUtil {

    public static void validate(ServerPublicKeyCredential serverPublicKeyCredential) {

        if (serverPublicKeyCredential == null) {
            throw new ConstraintViolationException("serverPublicKeyCredential must not be null");
        }
        if (serverPublicKeyCredential.getId() == null) {
            throw new ConstraintViolationException("id must not be null");
        }
        if (serverPublicKeyCredential.getRawId() == null) {
            throw new ConstraintViolationException("rawId must not be null");
        }
        if (serverPublicKeyCredential.getType() == null) {
            throw new ConstraintViolationException("type must not be null");
        }
        if (serverPublicKeyCredential.getResponse() == null) {
            throw new ConstraintViolationException("response must not be null");
        }
    }
}
