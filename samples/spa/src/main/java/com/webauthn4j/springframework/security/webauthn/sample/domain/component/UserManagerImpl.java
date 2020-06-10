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

import com.webauthn4j.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import com.webauthn4j.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import com.webauthn4j.springframework.security.webauthn.sample.domain.repository.AuthenticatorEntityRepository;
import com.webauthn4j.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.terasoluna.gfw.common.message.ResultMessages;

/**
 * {@inheritDoc}
 */
@Component
@Transactional
public class UserManagerImpl implements UserManager {

    private final ModelMapper modelMapper;

    private final UserEntityRepository userEntityRepository;
    private final AuthenticatorEntityRepository authenticatorEntityRepository;

    @Autowired
    public UserManagerImpl(ModelMapper mapper, UserEntityRepository userEntityRepository, AuthenticatorEntityRepository authenticatorEntityRepository) {
        this.modelMapper = mapper;
        this.userEntityRepository = userEntityRepository;
        this.authenticatorEntityRepository = authenticatorEntityRepository;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserEntity findById(int id) {
        return userEntityRepository.findById(id)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND)));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserDetails loadUserByUsername(String username) {
        return userEntityRepository.findOneByEmailAddress(username)
                .orElseThrow(() -> new UsernameNotFoundException(String.format("UserEntity with username'%s' is not found.", username)));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserEntity createUser(UserEntity user) {
        userEntityRepository.findOneByEmailAddress(user.getEmailAddress()).ifPresent((retrievedUserEntity) -> {
            throw new WebAuthnSampleBusinessException(ResultMessages.error().add(MessageCodes.Error.User.EMAIL_ADDRESS_IS_ALREADY_USED));
        });
        return userEntityRepository.save(user);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void updateUser(UserEntity user) {

        UserEntity userEntity = userEntityRepository.findById(user.getId())
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND)));
        userEntityRepository.save(userEntity);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void deleteUser(String username) {
        UserEntity userEntity = userEntityRepository.findOneByEmailAddress(username)
                .orElseThrow(() -> new UsernameNotFoundException(String.format("UserEntity with username'%s' is not found.", username)));
        userEntityRepository.delete(userEntity);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void deleteUser(int id) {
        userEntityRepository.findById(id)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND)));
        userEntityRepository.deleteById(id);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void changePassword(String oldPassword, String newPassword) {
        UserEntity currentUserEntity = getCurrentUser();

        if (currentUserEntity == null) {
            // This would indicate bad coding somewhere
            throw new AccessDeniedException(
                    "Can't change rawPassword as no Authentication object found in context "
                            + "for current user.");
        }

        currentUserEntity.setPassword(newPassword);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean userExists(String username) {
        return userEntityRepository.findOneByEmailAddress(username).isPresent();
    }

    /**
     * return current login user
     *
     * @return login user
     */
    private UserEntity getCurrentUser() {
        return (UserEntity) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

}
