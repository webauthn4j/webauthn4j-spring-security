package net.sharplab.springframework.security.webauthn.sample.app.api;


public class AuthResponse {
    private AuthStatus status;

    public AuthResponse(AuthStatus status){
        this.status = status;
    }

    public AuthStatus getStatus() {
        return status;
    }

    public void setStatus(AuthStatus status) {
        this.status = status;
    }
}
