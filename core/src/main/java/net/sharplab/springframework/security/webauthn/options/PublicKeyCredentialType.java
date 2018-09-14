package net.sharplab.springframework.security.webauthn.options;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum  PublicKeyCredentialType {
    PUBLIC_KEY("public-key");

    private final String value;

    PublicKeyCredentialType(String value){
        this.value = value;
    }

    @JsonCreator
    public static PublicKeyCredentialType create(String value) {
        switch (value) {
            case "public-key":
                return PUBLIC_KEY;
            default:
                throw new IllegalArgumentException("value is out of range");
        }
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
