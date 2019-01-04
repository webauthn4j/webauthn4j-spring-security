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

package net.sharplab.springframework.security.webauthn.sample.domain.repository;

import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/**
 * グループレポジトリ
 */
public interface GroupEntityRepository extends JpaRepository<GroupEntity, Integer> {

    Optional<GroupEntity> findOneByGroupName(String groupName);

    @Query("SELECT g FROM GroupEntity g WHERE g.groupName LIKE %:keyword% ORDER BY g.id")
    Page<GroupEntity> findAllByKeyword(Pageable pageable, @Param("keyword") String keyword);

}
