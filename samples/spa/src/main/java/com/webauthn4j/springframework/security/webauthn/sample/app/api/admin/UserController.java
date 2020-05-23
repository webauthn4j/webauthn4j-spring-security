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

package com.webauthn4j.springframework.security.webauthn.sample.app.api.admin;

import com.webauthn4j.springframework.security.webauthn.sample.app.util.AppSpecificMapper;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/admin/user")
public class UserController {

    private final UserService userService;

    private final AppSpecificMapper mapper;

    @Autowired
    public UserController(UserService userService, AppSpecificMapper mapper) {
        this.userService = userService;
        this.mapper = mapper;
    }

    @GetMapping("/")
    public Page<UserForm> list(Pageable pageable, Model model, @RequestParam(required = false, value = "keyword") String keyword) {
        Page<UserEntity> users = userService.findAllByKeyword(pageable, keyword);
        return mapper.mapToUserPage(users);
    }

    @GetMapping("/{id}")
    public UserForm show(@PathVariable(value = "id") int id) {
        UserEntity userEntity = userService.findOne(id);
        return mapper.mapToUserForm(userEntity);
    }

    @PostMapping
    public UserForm create(@Valid @RequestBody UserCreateForm userCreateForm) {
        UserEntity userEntity = mapper.mapForCreate(userCreateForm);
        UserEntity createdUserEntity = userService.create(userEntity);
        return mapper.mapToUserForm(createdUserEntity);
    }

    @PutMapping("/{id}")
    public UserForm update(@PathVariable(value = "id") int id, @Valid @RequestBody UserUpdateForm userUpdateForm) {
        UserEntity updatedUserEntity = userService.update(id, user -> mapper.mapForUpdate(userUpdateForm, user));
        return mapper.mapToUserForm(updatedUserEntity);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable(value = "id") int id) {
        userService.delete(id);
    }
}
