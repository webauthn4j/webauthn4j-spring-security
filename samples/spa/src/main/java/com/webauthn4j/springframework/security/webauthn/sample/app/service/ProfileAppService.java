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
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;

public interface ProfileAppService {

    /**
     * find one user
     *
     * @param id userId
     * @return user
     */
    UserEntity findOne(int id);

    /**
     * create a userEntity
     *
     * @param userEntity userEntity
     * @return created userEntity
     */
    UserEntity create(UserEntity userEntity);

    /**
     * update the specified user
     *
     * @param id userId
     * @param profileUpdateForm profileUpdateForm
     */
    UserEntity update(int id, ProfileUpdateForm profileUpdateForm);

    /**
     * delete the specified user
     *
     * @param id userId
     */
    void delete(int id);
}
