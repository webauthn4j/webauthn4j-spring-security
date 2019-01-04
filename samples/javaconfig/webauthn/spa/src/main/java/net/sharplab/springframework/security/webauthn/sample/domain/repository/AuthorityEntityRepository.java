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

import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/**
 * 権限レポジトリ
 */
public interface AuthorityEntityRepository extends JpaRepository<AuthorityEntity, Integer> {

    Optional<AuthorityEntity> findOneByAuthority(String authority);

    @Query("SELECT a FROM AuthorityEntity a WHERE a.authority LIKE %:keyword% ORDER BY a.id")
    Page<AuthorityEntity> findAllByKeyword(Pageable pageable, @Param("keyword") String keyword);
}
