package net.sharplab.springframework.security.webauthn.endpoint;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum Status {

    OK("ok"),
    FAILED("failed");

    @JsonValue
    private String value;

    Status(String value) {
        this.value = value;
    }

    @JsonCreator
    public static Status create(String value) {
        switch (value) {
            case "ok":
                return OK;
            case "failed":
                return FAILED;
            default:
                throw new IllegalArgumentException();
        }
    }

    public String getValue() {
        return value;
    }
}
