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

import net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.GroupEntityRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.terasoluna.gfw.common.message.ResultMessages;

import java.util.List;

/**
 * グループサービス
 */
@Service
@Transactional
public class GroupServiceImpl implements GroupService {

    private final GroupEntityRepository groupEntityRepository;

    @Autowired
    public GroupServiceImpl(GroupEntityRepository groupEntityRepository) {
        this.groupEntityRepository = groupEntityRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public GroupEntity findOne(int id) {
        return groupEntityRepository.findById(id)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
    }

    @Override
    @Transactional(readOnly = true)
    public List<GroupEntity> findAll() {
        return groupEntityRepository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public Page<GroupEntity> findAll(Pageable pageable) {
        return groupEntityRepository.findAll(pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<GroupEntity> findAllByKeyword(Pageable pageable, String keyword) {
        if (keyword == null) {
            return groupEntityRepository.findAll(pageable);
        } else {
            return groupEntityRepository.findAllByKeyword(pageable, keyword);
        }
    }

    @Override
    public GroupEntity create(GroupEntity groupEntity) {
        return groupEntityRepository.save(groupEntity);
    }

    @Override
    public GroupEntity update(GroupEntity groupEntity) {
        return groupEntityRepository.findById(groupEntity.getId())
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
    }

    @Override
    public void delete(int id) {
        groupEntityRepository.deleteById(id);
    }
}
