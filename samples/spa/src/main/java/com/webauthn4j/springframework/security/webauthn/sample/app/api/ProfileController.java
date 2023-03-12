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

package com.webauthn4j.springframework.security.webauthn.sample.app.api;

import com.webauthn4j.springframework.security.webauthn.sample.app.api.validator.spring.ProfileCreateFormValidator;
import com.webauthn4j.springframework.security.webauthn.sample.app.api.validator.spring.ProfileUpdateFormValidator;
import com.webauthn4j.springframework.security.webauthn.sample.app.service.ProfileAppService;
import com.webauthn4j.springframework.security.webauthn.sample.app.util.AppSpecificMapper;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private final ProfileAppService profileAppService;

    private final AppSpecificMapper mapper;

    @Autowired
    private ProfileCreateFormValidator profileCreateFormValidator;

    @Autowired
    private ProfileUpdateFormValidator profileUpdateFormValidator;

    @Autowired
    public ProfileController(ProfileAppService profileAppService, AppSpecificMapper mapper) {
        this.profileAppService = profileAppService;
        this.mapper = mapper;
    }

    @InitBinder("profileCreateForm")
    public void initProfileCreateFormBinder(WebDataBinder binder) {
        binder.addValidators(profileCreateFormValidator);
    }

    @InitBinder("profileUpdateForm")
    public void initProfileUpdateFormBinder(WebDataBinder binder) {
        binder.addValidators(profileUpdateFormValidator);
    }

    @GetMapping
    public ProfileForm show(@AuthenticationPrincipal UserEntity loginUserEntity) {
        UserEntity userEntity = profileAppService.findOne(loginUserEntity.getId());
        return mapper.mapToProfileForm(userEntity);
    }

    @PostMapping
    public ProfileForm create(@Valid @RequestBody ProfileCreateForm profileCreateForm) {
        UserEntity userEntity = mapper.mapForCreate(profileCreateForm);
        UserEntity createdUserEntity = profileAppService.create(userEntity);
        return mapper.mapToProfileForm(createdUserEntity);
    }

    @PutMapping
    public ProfileForm update(@AuthenticationPrincipal UserEntity loginUserEntity, @Valid @RequestBody ProfileUpdateForm profileUpdateForm) {
        int id = loginUserEntity.getId();
        UserEntity updatedUserEntity = profileAppService.update(id, profileUpdateForm);
        return mapper.mapToProfileForm(updatedUserEntity);
    }

    @DeleteMapping
    public void delete(@AuthenticationPrincipal UserEntity loginUserEntity) {
        int id = loginUserEntity.getId();
        profileAppService.delete(id);
        SecurityContextHolder.clearContext();
    }

}
