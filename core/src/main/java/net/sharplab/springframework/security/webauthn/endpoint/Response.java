package net.sharplab.springframework.security.webauthn.endpoint;

import java.util.Objects;

public class Response<T> {
    private T data;
    private String errorMessage;

    public Response(T data) {
        this.data = data;
    }

    public Response(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public T getData() {
        return data;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Response<?> response = (Response<?>) o;
        return Objects.equals(data, response.data) &&
                Objects.equals(errorMessage, response.errorMessage);
    }

    @Override
    public int hashCode() {

        return Objects.hash(data, errorMessage);
    }
}
