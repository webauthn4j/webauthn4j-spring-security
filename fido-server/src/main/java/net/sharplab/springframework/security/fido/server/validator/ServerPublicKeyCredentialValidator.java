package net.sharplab.springframework.security.fido.server.validator;

import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.fido.server.endpoint.ServerAuthenticatorResponse;
import net.sharplab.springframework.security.fido.server.endpoint.ServerPublicKeyCredential;
import net.sharplab.springframework.security.fido.server.util.BeanAssertUtil;
import net.sharplab.springframework.security.webauthn.exception.BadCredentialIdException;

public class ServerPublicKeyCredentialValidator<T extends ServerAuthenticatorResponse> {

    public void validate(ServerPublicKeyCredential<T> serverPublicKeyCredential) {

        BeanAssertUtil.validate(serverPublicKeyCredential);

        if (!serverPublicKeyCredential.getId().equals(serverPublicKeyCredential.getRawId())) {
            throw new BadCredentialIdException("id and rawId doesn't match");
        }

        try {
            Base64UrlUtil.decode(serverPublicKeyCredential.getId());
        } catch (IllegalArgumentException e) {
            throw new BadCredentialIdException("id cannot be parsed as base64url", e);
        }
    }
}
