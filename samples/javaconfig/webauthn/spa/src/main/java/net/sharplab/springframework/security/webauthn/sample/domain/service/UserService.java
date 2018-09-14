package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.function.Consumer;

/**
 * User service
 */
public interface UserService {

    /**
     * find one user
     *
     * @param id userId
     * @return user
     */
    User findOne(int id);

    /**
     * find all users
     *
     * @return user list
     */
    List<User> findAll();

    /**
     * find all users with paging
     *
     * @param pageable paging info
     * @return user list
     */
    Page<User> findAll(Pageable pageable);

    /**
     * find all users by keyword
     *
     * @param pageable paging info
     * @param keyword  keyword
     * @return user list
     */
    Page<User> findAllByKeyword(Pageable pageable, String keyword);

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
    User update(int id, Consumer<User> consumer);

    /**
     * delete the specified user
     *
     * @param id userId
     */
    void delete(int id);

}
