package net.sharplab.springframework.security.fido.server.endpoint;

public abstract class ServerResponseBase implements ServerResponse {

    private Status status;
    private String errorMessage;

    public ServerResponseBase(Status status, String errorMessage) {
        this.status = status;
        this.errorMessage = errorMessage;
    }

    public ServerResponseBase() {
        this.status = Status.OK;
        this.errorMessage = "";
    }

    @Override
    public Status getStatus() {
        return status;
    }

    @Override
    public String getErrorMessage() {
        return errorMessage;
    }

}
