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