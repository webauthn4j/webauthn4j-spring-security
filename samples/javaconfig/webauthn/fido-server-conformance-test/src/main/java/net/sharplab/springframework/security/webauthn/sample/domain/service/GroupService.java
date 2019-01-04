package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
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
    GroupEntity findOne(int id);

    /**
     * find all groups
     *
     * @return group list
     */
    List<GroupEntity> findAll();

    /**
     * find all groups with paging
     *
     * @param pageable paging info
     * @return group list
     */
    Page<GroupEntity> findAll(Pageable pageable);

    /**
     * find all groups by keyword
     *
     * @param pageable paging info
     * @param keyword  keyword
     * @return group list
     */
    Page<GroupEntity> findAllByKeyword(Pageable pageable, String keyword);

    /**
     * create a groupEntity
     *
     * @param groupEntity groupEntity
     * @return created groupEntity
     */
    GroupEntity create(GroupEntity groupEntity);

    /**
     * update the specified groupEntity
     *
     * @param groupEntity groupEntity
     * @return updated groupEntity
     */
    GroupEntity update(GroupEntity groupEntity);

    /**
     * delete the specified group
     *
     * @param id groupId
     */
    void delete(int id);

}
