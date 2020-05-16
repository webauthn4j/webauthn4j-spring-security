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

package com.webauthn4j.springframework.security.webauthn.sample.domain.constant;

import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import org.modelmapper.TypeToken;
import org.springframework.data.domain.PageImpl;

import java.lang.reflect.Type;
import java.util.ArrayList;

/**
 * ModelMapper TypeToken constants
 */
public class DomainTypeTokens {

    public static final Type UserEntityList = new TypeToken<ArrayList<GroupEntity>>() {
    }.getType();
    public static final Type GroupEntityList = new TypeToken<ArrayList<GroupEntity>>() {
    }.getType();
    public static final Type AuthorityEntityList = new TypeToken<ArrayList<AuthorityEntity>>() {
    }.getType();
    public static final Type AuthenticatorEntityList = new TypeToken<ArrayList<AuthenticatorEntity>>() {
    }.getType();

    public static final Type UserPage = new TypeToken<PageImpl<UserEntity>>() {
    }.getType();
    public static final Type GroupPage = new TypeToken<PageImpl<GroupEntity>>() {
    }.getType();
    public static final Type AuthorityPage = new TypeToken<PageImpl<AuthorityEntity>>() {
    }.getType();

    private DomainTypeTokens() {
    }
}
