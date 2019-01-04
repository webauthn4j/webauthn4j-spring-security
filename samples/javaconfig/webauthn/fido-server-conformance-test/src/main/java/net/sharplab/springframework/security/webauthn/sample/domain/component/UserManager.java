package net.sharplab.springframework.security.webauthn.sample.domain.component;


import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * ユーザー詳細サービス
 */
public interface UserManager extends UserDetailsService {

    /**
     * create a userEntity
     *
     * @param userEntity userEntity
     * @return created userEntity
     */
    UserEntity createUser(UserEntity userEntity);

    /**
     * update a userEntity
     *
     * @param userEntity userEntity
     */
    void updateUser(UserEntity userEntity);

    /**
     * delete the specified user
     *
     * @param username username
     */
    void deleteUser(String username);

    /**
     * delete the specified user
     *
     * @param id userId
     */
    void deleteUser(int id);

    /**
     * update password
     *
     * @param oldPassword old password
     * @param newPassword new password
     */
    void changePassword(String oldPassword, String newPassword);

    /**
     * return true if user exists
     *
     * @param username user name
     * @return true if user exists
     */
    boolean userExists(String username);

    /**
     * find a user by id
     *
     * @param id userId
     * @return user
     */
    UserEntity findById(int id);

}
