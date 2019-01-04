package net.sharplab.springframework.security.webauthn.sample.app.security;

import net.sharplab.springframework.security.fido.server.endpoint.UsernameNotFoundHandler;
import net.sharplab.springframework.security.webauthn.sample.domain.component.UserManager;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;

import java.util.Collections;

public class SampleUsernameNotFoundHandler implements UsernameNotFoundHandler {

    private UserManager userManager;

    public SampleUsernameNotFoundHandler(UserManager userManager) {
        this.userManager = userManager;
    }

    @Override
    public void onUsernameNotFound(String loginUsername) {
        byte[] userHandle = new byte[0]; //TODO
        UserEntity userEntity = new UserEntity();
        userEntity.setUserHandle(userHandle);
        userEntity.setEmailAddress(loginUsername);
        userEntity.setLastName("dummy");
        userEntity.setFirstName("dummy");
        userEntity.setSingleFactorAuthenticationAllowed(false);
        userEntity.setPassword("dummy");
        userEntity.setGroups(Collections.emptyList());
        userEntity.setAuthorities(Collections.emptyList());
        userEntity.setAuthenticators(Collections.emptyList());
        userManager.createUser(userEntity);
    }
}
