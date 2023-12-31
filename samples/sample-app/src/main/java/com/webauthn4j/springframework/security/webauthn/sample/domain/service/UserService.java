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

package com.webauthn4j.springframework.security.webauthn.sample.domain.service;

import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.function.Consumer;

/**
 * User service
 */
public interface UserService {

    /**
     * find one user
     *
     * @param id userId
     * @return user
     */
    UserEntity findOne(int id);

    /**
     * find all users
     *
     * @return user list
     */
    List<UserEntity> findAll();

    /**
     * find all users with paging
     *
     * @param pageable paging info
     * @return user list
     */
    Page<UserEntity> findAll(Pageable pageable);

    /**
     * find all users by keyword
     *
     * @param pageable paging info
     * @param keyword  keyword
     * @return user list
     */
    Page<UserEntity> findAllByKeyword(Pageable pageable, String keyword);

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
     */
    UserEntity update(int id, Consumer<UserEntity> consumer);

    /**
     * delete the specified user
     *
     * @param id userId
     */
    void delete(int id);

}
