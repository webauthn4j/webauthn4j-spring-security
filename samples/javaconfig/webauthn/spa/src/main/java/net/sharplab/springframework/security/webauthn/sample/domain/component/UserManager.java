package net.sharplab.springframework.security.webauthn.sample.domain.component;


import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * ユーザー詳細サービス
 */
public interface UserManager extends UserDetailsService {

    /**
     * create a user
     *
     * @param user user
     * @return created user
     */
    User createUser(User user);

    /**
     * update a user
     *
     * @param user user
     */
    void updateUser(User user);

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
    User findById(int id);

}
