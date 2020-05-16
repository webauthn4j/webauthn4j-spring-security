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

package com.webauthn4j.springframework.security.webauthn.sample.domain.component;

import com.webauthn4j.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens;
import com.webauthn4j.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import com.webauthn4j.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import com.webauthn4j.springframework.security.webauthn.sample.domain.repository.AuthorityEntityRepository;
import com.webauthn4j.springframework.security.webauthn.sample.domain.repository.GroupEntityRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.terasoluna.gfw.common.message.ResultMessages;

import java.util.List;

/**
 * {@inheritDoc}
 */
@Component
@Transactional
public class GroupManagerImpl implements GroupManager {

    private final ModelMapper modelMapper;

    private final UserEntityRepository userEntityRepository;
    private final GroupEntityRepository groupEntityRepository;
    private final AuthorityEntityRepository authorityEntityRepository;

    @Autowired
    public GroupManagerImpl(ModelMapper mapper, UserEntityRepository userEntityRepository, GroupEntityRepository groupEntityRepository, AuthorityEntityRepository authorityEntityRepository) {
        this.modelMapper = mapper;
        this.userEntityRepository = userEntityRepository;
        this.groupEntityRepository = groupEntityRepository;
        this.authorityEntityRepository = authorityEntityRepository;
    }


    @Override
    public GroupEntity findGroup(int groupId) {
        return groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
    }

    @Override
    public List<GroupEntity> findAllGroups() {
        return groupEntityRepository.findAll();
    }

    @Override
    public List<UserEntity> findUsersInGroup(int groupId) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        return groupEntity.getUsers();
    }

    @Override
    public List<UserEntity> findUsersInGroup(String groupName) {
        GroupEntity groupEntity = groupEntityRepository.findOneByGroupName(groupName)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        return groupEntity.getUsers();
    }

    @Override
    public GroupEntity createGroup(GroupEntity groupEntity) {
        return groupEntityRepository.save(groupEntity);
    }

    @Override
    public void deleteGroup(int groupId) {
        groupEntityRepository.deleteById(groupId);
    }

    @Override
    public void renameGroup(int groupId, String newName) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        groupEntity.setGroupName(newName);
    }

    @Override
    public void addUserToGroup(int userId, int groupId) {
        UserEntity userEntityEntity = userEntityRepository.findById(userId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND)));

        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        groupEntity.getUsers().add(userEntityEntity);
    }

    @Override
    public void removeUserFromGroup(int userId, int groupId) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        groupEntity.getUsers().remove(userId);
    }

    @Override
    public List<AuthorityEntity> findGroupAuthorities(int groupId) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        return modelMapper.map(groupEntity.getAuthorities(), DomainTypeTokens.AuthorityEntityList);
    }

    @Override
    public void addGroupAuthority(int groupId, AuthorityEntity authority) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        AuthorityEntity authorityEntityEntity = modelMapper.map(authority, AuthorityEntity.class);
        groupEntity.getAuthorities().add(authorityEntityEntity);
    }

    @Override
    public void removeGroupAuthority(int groupId, AuthorityEntity authority) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        AuthorityEntity authorityEntityEntity = authorityEntityRepository.findById(authority.getId())
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Authority.AUTHORITY_NOT_FOUND)));

        groupEntity.getAuthorities().remove(authorityEntityEntity);
    }

}
