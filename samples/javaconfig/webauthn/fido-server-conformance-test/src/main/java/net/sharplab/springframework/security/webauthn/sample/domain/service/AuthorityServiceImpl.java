package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.dto.AuthorityUpdateDto;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.AuthorityEntityRepository;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.GroupEntityRepository;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.terasoluna.gfw.common.message.ResultMessages;

import java.util.List;
import java.util.Set;

/**
 * 権限サービス
 */
@Service
@Transactional
public class AuthorityServiceImpl implements AuthorityService {

    private final UserEntityRepository userEntityRepository;
    private final GroupEntityRepository groupEntityRepository;
    private final AuthorityEntityRepository authorityEntityRepository;

    @Autowired
    public AuthorityServiceImpl(UserEntityRepository userEntityRepository, GroupEntityRepository groupEntityRepository, AuthorityEntityRepository authorityEntityRepository) {
        this.userEntityRepository = userEntityRepository;
        this.groupEntityRepository = groupEntityRepository;
        this.authorityEntityRepository = authorityEntityRepository;
    }

    @Override
    public AuthorityEntity findOne(Integer authorityId) {
        return authorityEntityRepository.findById(authorityId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Authority.AUTHORITY_NOT_FOUND)));
    }

    @Override
    @Transactional(readOnly = true)
    public List<AuthorityEntity> findAll() {
        return authorityEntityRepository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public Page<AuthorityEntity> findAll(Pageable pageable) {
        return authorityEntityRepository.findAll(pageable);
    }

    @Override
    public Page<AuthorityEntity> findAllByKeyword(Pageable pageable, String keyword) {
        if (keyword == null) {
            return authorityEntityRepository.findAll(pageable);
        } else {
            return authorityEntityRepository.findAllByKeyword(pageable, keyword);
        }

    }

    @Override
    public AuthorityEntity update(AuthorityEntity authorityEntity) {
        return authorityEntityRepository.findById(authorityEntity.getId()).orElseThrow(() ->
                new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Authority.AUTHORITY_NOT_FOUND)));
    }

    @Override
    public AuthorityEntity update(AuthorityUpdateDto authorityUpdateDto) {
        AuthorityEntity retrievedAuthorityEntity = authorityEntityRepository.findById(authorityUpdateDto.getId())
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Authority.AUTHORITY_NOT_FOUND)));
        List<UserEntity> userEntityList = userEntityRepository.findAllById(authorityUpdateDto.getUsers());
        List<GroupEntity> groupEntityList = groupEntityRepository.findAllById(authorityUpdateDto.getGroups());
        retrievedAuthorityEntity.setUsers(userEntityList);
        retrievedAuthorityEntity.setGroups(groupEntityList);
        return retrievedAuthorityEntity;
    }

    @Override
    public Page<UserEntity> findAllCandidateUsersByKeyword(Pageable pageable, String keyword) {
        if (keyword == null) {
            return userEntityRepository.findAll(pageable);
        } else {
            return userEntityRepository.findAllByKeyword(pageable, keyword);
        }
    }

    @Override
    public Page<GroupEntity> findAllCandidateGroupsByKeyword(Pageable pageable, String keyword) {
        if (keyword == null) {
            return groupEntityRepository.findAll(pageable);
        } else {
            return groupEntityRepository.findAllByKeyword(pageable, keyword);
        }
    }


}
