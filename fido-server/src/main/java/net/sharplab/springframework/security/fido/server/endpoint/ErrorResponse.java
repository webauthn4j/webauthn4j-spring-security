package net.sharplab.springframework.security.fido.server.endpoint;


public class ErrorResponse extends ServerResponseBase {

    public ErrorResponse(String errorMessage) {
        super(Status.FAILED, errorMessage);
    }

}
