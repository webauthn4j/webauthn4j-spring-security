/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.springframework.security.fido.server.endpoint;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

public enum Status {

    OK("ok"),
    FAILED("failed");

    @JsonValue
    private String value;

    Status(String value) {
        this.value = value;
    }

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

    @JsonCreator
    public static Status fromJson(String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, Status.class);
        }
    }

    public String getValue() {
        return value;
    }
}
