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

package com.webauthn4j.springframework.security.endpoint;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.webauthn4j.springframework.security.converter.jackson.deserializer.ByteArraySerializer;
import com.webauthn4j.springframework.security.converter.jackson.serializer.ByteArrayDeserializer;
import org.jspecify.annotations.NonNull;

/**
 * A mix-in for {@link com.webauthn4j.data.PublicKeyCredentialUserEntity} not to fix
 * how to serialize it.
 */
@SuppressWarnings("java:S1610")
public abstract class PublicKeyCredentialUserEntityMixin {

    @JsonDeserialize(using = ByteArrayDeserializer.class)
    @JsonSerialize(using = ByteArraySerializer.class)
    abstract String getId();

    @JsonCreator
    protected PublicKeyCredentialUserEntityMixin(
            @NonNull @JsonProperty("id") byte[] id,
            @NonNull @JsonProperty("name") String name,
            @NonNull @JsonProperty("displayName") String displayName){}

}
