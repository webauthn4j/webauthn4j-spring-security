package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.model.Group;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

/**
 * group service
 */
public interface GroupService {

    /**
     * find one group
     *
     * @param id groupId
     * @return group
     */
    Group findOne(int id);

    /**
     * find all groups
     *
     * @return group list
     */
    List<Group> findAll();

    /**
     * find all groups with paging
     *
     * @param pageable paging info
     * @return group list
     */
    Page<Group> findAll(Pageable pageable);

    /**
     * find all groups by keyword
     *
     * @param pageable paging info
     * @param keyword  keyword
     * @return group list
     */
    Page<Group> findAllByKeyword(Pageable pageable, String keyword);

    /**
     * create a group
     *
     * @param group group
     * @return created group
     */
    Group create(Group group);

    /**
     * update the specified group
     *
     * @param group group
     */
    void update(Group group);

    /**
     * delete the specified group
     *
     * @param id groupId
     */
    void delete(int id);

}
