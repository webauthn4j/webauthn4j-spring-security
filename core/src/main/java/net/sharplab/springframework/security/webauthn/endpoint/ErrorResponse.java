package net.sharplab.springframework.security.webauthn.endpoint;


public class ErrorResponse extends ServerResponseBase {

    public ErrorResponse(String errorMessage) {
        super(Status.FAILED, errorMessage);
    }

}
