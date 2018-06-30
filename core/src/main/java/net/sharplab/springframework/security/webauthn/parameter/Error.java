package net.sharplab.springframework.security.webauthn.parameter;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public class Error {
    private Type type;
    private String message;

    public Error(Type type, String message) {
        this.type = type;
        this.message = message;
    }

    public enum Type {

        NotAuthenticated("not_authenticated"),
        ServerError("server_error");

        @JsonValue
        private String value;

        Type(String value){
            this.value = value;
        }

        @JsonCreator
        public static Type create(String value){
            switch (value){
                case "not_authenticated":
                    return NotAuthenticated;
                case "server_error":
                    return ServerError;
                default:
                    throw new IllegalArgumentException();
            }
        }
    }
}
