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

package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.dto.AuthorityUpdateDto;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

/**
 * 権限サービス
 */
public interface AuthorityService {
    Page<AuthorityEntity> findAllByKeyword(Pageable pageable, String keyword);

    AuthorityEntity findOne(Integer authorityId);

    List<AuthorityEntity> findAll();

    Page<AuthorityEntity> findAll(Pageable pageable);

    AuthorityEntity update(AuthorityEntity authorityEntity);

    AuthorityEntity update(AuthorityUpdateDto authorityUpdateDto);

    Page<UserEntity> findAllCandidateUsersByKeyword(Pageable pageable, String keyword);

    Page<GroupEntity> findAllCandidateGroupsByKeyword(Pageable pageable, String keyword);
}