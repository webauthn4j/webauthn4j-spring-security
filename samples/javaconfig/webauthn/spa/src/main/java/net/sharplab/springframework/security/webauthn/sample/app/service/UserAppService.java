package net.sharplab.springframework.security.webauthn.sample.app.service;

import net.sharplab.springframework.security.webauthn.sample.app.api.admin.UserUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional
public interface UserAppService {

    /**
     * find one user
     *
     * @param id userId
     * @return user
     */
    UserEntity findOne(int id);

    /**
     * find all users
     *
     * @return find all users
     */
    List<UserEntity> findAll();

    /**
     * find all users with paging
     *
     * @param pageable paging info
     * @return user list
     */
    Page<UserEntity> findAll(Pageable pageable);

    /**
     * find all users by keyword
     *
     * @param pageable paging info
     * @param keyword  keyword
     * @return user list
     */
    Page<UserEntity> findAllByKeyword(Pageable pageable, String keyword);

    /**
     * create a userEntity
     *
     * @param userEntity userEntity
     * @return created userEntity
     */
    UserEntity create(UserEntity userEntity);

    /**
     * update the specified user
     *
     * @param id userId
     */
    UserEntity update(int id, UserUpdateForm userUpdateForm);

    /**
     * delete the specified user
     *
     * @param id userId
     */
    void delete(int id);
}
