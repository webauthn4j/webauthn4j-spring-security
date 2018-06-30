package net.sharplab.springframework.security.webauthn.condition;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public class Error {
    private Type type;
    private String message;

    public Error(Type type, String message) {
        this.type = type;
        this.message = message;
    }

    public Type getType() {
        return type;
    }

    public String getMessage() {
        return message;
    }

    public enum Type {

        NOT_AUTHENTICATED("not_authenticated"),
        SERVER_ERROR("server_error");

        @JsonValue
        private String value;

        Type(String value){
            this.value = value;
        }

        @JsonCreator
        public static Type create(String value){
            switch (value){
                case "not_authenticated":
                    return NOT_AUTHENTICATED;
                case "server_error":
                    return SERVER_ERROR;
                default:
                    throw new IllegalArgumentException();
            }
        }
    }
}
