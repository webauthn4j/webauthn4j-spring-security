/*
 *    Copyright 2002-2019 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.sample.app.service;

import net.sharplab.springframework.security.webauthn.sample.app.api.admin.UserUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.app.util.AppSpecificMapper;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class UserAppServiceImpl implements UserAppService {

    @Autowired
    private UserService userService;

    @Autowired
    private AppSpecificMapper mapper;

    @Transactional(readOnly = true)
    @Override
    public UserEntity findOne(int id) {
        return userService.findOne(id);
    }

    @Transactional(readOnly = true)
    @Override
    public List<UserEntity> findAll() {
        return userService.findAll();
    }

    @Transactional(readOnly = true)
    @Override
    public Page<UserEntity> findAll(Pageable pageable) {
        return userService.findAll(pageable);
    }

    @Transactional(readOnly = true)
    @Override
    public Page<UserEntity> findAllByKeyword(Pageable pageable, String keyword) {
        return userService.findAllByKeyword(pageable, keyword);
    }

    @Override
    public UserEntity create(UserEntity userEntity) {
        return userService.create(userEntity);
    }

    @Transactional
    @Override
    public UserEntity update(int id, UserUpdateForm userUpdateForm) {
        return userService.update(id, user -> mapper.mapForUpdate(userUpdateForm, user));
    }

    @Transactional
    @Override
    public void delete(int id) {
        delete(id);
    }
}
