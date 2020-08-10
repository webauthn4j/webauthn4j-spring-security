/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.springframework.security.webauthn.sample.test;

import com.webauthn4j.springframework.security.WebAuthnAuthenticationRequest;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationToken;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;

/**
 * SecurityContextFactory for WithMockUser
 */
public class WithMockWebAuthnUserSecurityContextFactory implements WithSecurityContextFactory<WithMockWebAuthnUser> {

    /**
     * Create a {@link SecurityContext} given an Annotation.
     *
     * @param user the {@link WithMockWebAuthnUser} to create the {@link SecurityContext}
     *             from. Cannot be null.
     * @return the {@link SecurityContext} to use. Cannot be null.
     */
    @Override
    public SecurityContext createSecurityContext(WithMockWebAuthnUser user) {

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        List<AuthorityEntity> authorities = Arrays.stream(user.authorities()).map((name) -> new AuthorityEntity(null, name)).collect(Collectors.toList());
        List<GroupEntity> groups = Arrays.stream(user.groups()).map(GroupEntity::new).collect(Collectors.toList());
        List<AuthenticatorEntity> authenticatorEntities =
                Arrays.stream(user.authenticators())
                        .map((name) -> {
                            AuthenticatorEntity authenticatorEntity = new AuthenticatorEntity();
                            authenticatorEntity.setName(name);
                            return authenticatorEntity;
                        })
                        .collect(Collectors.toList());

        UserEntity principal = new UserEntity();
        principal.setId(user.id());
        principal.setUserHandle(Base64UrlUtil.decode(user.userHandleBase64Url()));
        principal.setFirstName(user.firstName());
        principal.setLastName(user.lastName());
        principal.setEmailAddress(user.emailAddress());
        principal.setGroups(groups);
        principal.setAuthorities(authorities);
        principal.setAuthenticators(authenticatorEntities);
        principal.setLocked(user.locked());

        WebAuthnAuthenticationRequest request = mock(WebAuthnAuthenticationRequest.class);

        Authentication auth =
                new WebAuthnAuthenticationToken(principal, request, principal.getAuthorities());
        context.setAuthentication(auth);
        return context;
    }
}
