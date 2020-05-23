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

package com.webauthn4j.springframework.security.webauthn.sample.app.service;

import com.webauthn4j.springframework.security.webauthn.sample.app.api.ProfileUpdateForm;
import com.webauthn4j.springframework.security.webauthn.sample.app.util.AppSpecificMapper;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class ProfileAppServiceImpl implements ProfileAppService {

    private final UserService userService;

    private final AppSpecificMapper mapper;

    @Autowired
    public ProfileAppServiceImpl(UserService userService, AppSpecificMapper mapper) {
        this.userService = userService;
        this.mapper = mapper;
    }

    @Override
    public UserEntity findOne(int id) {
        return userService.findOne(id);
    }

    @Override
    public UserEntity create(UserEntity userEntity) {
        return userService.create(userEntity);
    }

    @Override
    public UserEntity update(int id, ProfileUpdateForm profileUpdateForm) {
        return userService.update(id, user -> mapper.mapForUpdate(profileUpdateForm, user));
    }

    @Override
    public void delete(int id) {
        userService.delete(id);
    }
}
