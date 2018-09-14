package net.sharplab.springframework.security.webauthn.sample.app.service;

import net.sharplab.springframework.security.webauthn.sample.app.api.ProfileUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;

public interface ProfileAppService {

    /**
     * find one user
     *
     * @param id userId
     * @return user
     */
    User findOne(int id);

    /**
     * create a user
     *
     * @param user user
     * @return created user
     */
    User create(User user);

    /**
     * update the specified user
     *
     * @param id userId
     */
    User update(int id, ProfileUpdateForm profileUpdateForm);

    /**
     * delete the specified user
     *
     * @param id userId
     */
    void delete(int id);
}
