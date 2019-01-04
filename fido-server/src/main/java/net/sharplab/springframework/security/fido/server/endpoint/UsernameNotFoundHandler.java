package net.sharplab.springframework.security.fido.server.endpoint;

public interface UsernameNotFoundHandler {

    void onUsernameNotFound(String loginUsername);

}
