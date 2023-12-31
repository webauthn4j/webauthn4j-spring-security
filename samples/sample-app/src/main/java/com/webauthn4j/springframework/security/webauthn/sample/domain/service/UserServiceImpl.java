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

import com.webauthn4j.springframework.security.webauthn.sample.domain.component.UserManager;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.function.Consumer;

/**
 * Implementation for {@link UserService}
 */
@Service
@Transactional
public class UserServiceImpl implements UserService {

    private final UserEntityRepository userEntityRepository;
    private final UserManager userManager;

    @Autowired
    public UserServiceImpl(UserEntityRepository userEntityRepository, UserManager userManager) {
        this.userEntityRepository = userEntityRepository;
        this.userManager = userManager;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserEntity findOne(int id) {
        return userManager.findById(id);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<UserEntity> findAll() {
        return userEntityRepository.findAll();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Page<UserEntity> findAll(Pageable pageable) {
        return userEntityRepository.findAll(pageable);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Page<UserEntity> findAllByKeyword(Pageable pageable, String keyword) {
        if (keyword == null) {
            return userEntityRepository.findAll(pageable);
        } else {
            return userEntityRepository.findAllByKeyword(pageable, keyword);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserEntity create(UserEntity userEntity) {
        return userManager.createUser(userEntity);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserEntity update(int id, Consumer<UserEntity> consumer) {
        UserEntity userEntity = findOne(id);
        consumer.accept(userEntity);
        userManager.updateUser(userEntity);
        return userEntity;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void delete(int id) {
        userManager.deleteUser(id);
    }
}
