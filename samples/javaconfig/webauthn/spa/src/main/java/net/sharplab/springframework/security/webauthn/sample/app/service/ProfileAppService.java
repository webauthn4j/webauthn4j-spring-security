package net.sharplab.springframework.security.webauthn.sample.app.service;

import net.sharplab.springframework.security.webauthn.sample.app.api.ProfileUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;

public interface ProfileAppService {

    /**
     * find one user
     *
     * @param id userId
     * @return user
     */
    UserEntity findOne(int id);

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
    UserEntity update(int id, ProfileUpdateForm profileUpdateForm);

    /**
     * delete the specified user
     *
     * @param id userId
     */
    void delete(int id);
}
