/*
 *    Copyright 2002-2019 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

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
