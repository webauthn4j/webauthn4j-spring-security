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

package com.webauthn4j.springframework.security.webauthn.sample.app.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.springframework.security.webauthn.sample.app.config.AppConfig;
import com.webauthn4j.springframework.security.webauthn.sample.app.service.ProfileAppService;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import com.webauthn4j.springframework.security.webauthn.sample.test.WithMockWebAuthnUser;
import com.webauthn4j.springframework.security.webauthn.sample.test.app.config.TestSecurityConfig;
import com.webauthn4j.springframework.security.webauthn.sample.test.infrastructure.config.InfrastructureMockConfig;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.UUIDUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.UUID;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(ProfileController.class)
@Import(value = {TestSecurityConfig.class, AppConfig.class, InfrastructureMockConfig.class})
public class ProfileControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockBean
    ProfileAppService profileAppService;

    @Autowired
    ObjectMapper objectMapper;

    @Test
    @WithMockWebAuthnUser(id = 1, firstName = "John", lastName = "Doe", emailAddress = "john.doe@example.com", authorities = {"ROLE_USER"}, authenticators = {})
    public void show_test() throws Exception {
        int userId = 1;

        UserEntity userEntity = new UserEntity();
        userEntity.setUserHandle(new byte[0]);
        userEntity.setId(userId);
        userEntity.setFirstName("John");
        userEntity.setLastName("Doe");
        userEntity.setEmailAddress("john.doe@example.com");
        userEntity.setAuthenticators(Collections.emptyList());
        userEntity.setAuthorities(Collections.singletonList(new AuthorityEntity(0, "SINGLE_FACTOR_AUTHN_ALLOWED")));

        when(profileAppService.findOne(userId)).thenReturn(userEntity);

        //When
        mvc.perform(get("/api/profile"))
                //Then
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(1)))
                .andExpect(jsonPath("$.userHandle", is("")))
                .andExpect(jsonPath("$.firstName", is("John")))
                .andExpect(jsonPath("$.lastName", is("Doe")))
                .andExpect(jsonPath("$.emailAddress", is("john.doe@example.com")))
                .andExpect(jsonPath("$.authenticators", is(empty())))
                .andExpect(jsonPath("$.singleFactorAuthenticationAllowed", is(true)))
        ;
    }

    @Test
    @WithAnonymousUser
    public void create_test() throws Exception {

        ProfileCreateForm userCreateForm = new ProfileCreateForm();
        userCreateForm.setUserHandle("ORZClsZpTvWrYGl7mXL5Wg");
        userCreateForm.setFirstName("John");
        userCreateForm.setLastName("Doe");
        userCreateForm.setEmailAddress("john.doe@example.com");
        userCreateForm.setPassword("password");
        userCreateForm.setAuthenticators(Collections.emptyList());
        userCreateForm.setSingleFactorAuthenticationAllowed(true);

        UserEntity userEntity = new UserEntity();
        userEntity.setId(1);
        userEntity.setUserHandle(Base64UrlUtil.decode("ORZClsZpTvWrYGl7mXL5Wg"));
        userEntity.setFirstName("John");
        userEntity.setLastName("Doe");
        userEntity.setEmailAddress("john.doe@example.com");
        userEntity.setAuthenticators(Collections.emptyList());
        userEntity.setAuthorities(Collections.singletonList(new AuthorityEntity(0, "SINGLE_FACTOR_AUTHN_ALLOWED")));

        when(profileAppService.create(any())).thenReturn(userEntity);

        //When
        mvc.perform(
                post("/api/profile")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userCreateForm))
                        .with(SecurityMockMvcRequestPostProcessors.csrf())
        )
                //Then
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(1)))
                .andExpect(jsonPath("$.userHandle", is("ORZClsZpTvWrYGl7mXL5Wg")))
                .andExpect(jsonPath("$.firstName", is("John")))
                .andExpect(jsonPath("$.lastName", is("Doe")))
                .andExpect(jsonPath("$.emailAddress", is("john.doe@example.com")))
                .andExpect(jsonPath("$.authenticators", is(empty())))
                .andExpect(jsonPath("$.singleFactorAuthenticationAllowed", is(true)))
        ;
        verify(profileAppService).create(any());
    }

    @Test
    @WithMockWebAuthnUser(id = 1, firstName = "John", lastName = "Doe", emailAddress = "john.doe@example.com", authorities = {"ROLE_USER"}, authenticators = {})
    public void update_test() throws Exception {
        int userId = 1;

        byte[] userHandle = UUIDUtil.convertUUIDToBytes(UUID.randomUUID());

        ProfileUpdateForm userUpdateForm = new ProfileUpdateForm();
        userUpdateForm.setUserHandle(Base64UrlUtil.encodeToString(userHandle));
        userUpdateForm.setFirstName("John");
        userUpdateForm.setLastName("Smith");
        userUpdateForm.setEmailAddress("john.smith@example.com");
        userUpdateForm.setAuthenticators(Collections.emptyList());
        userUpdateForm.setSingleFactorAuthenticationAllowed(true);

        UserEntity userEntity = new UserEntity();
        userEntity.setId(userId);
        userEntity.setUserHandle(userHandle);
        userEntity.setId(userId);
        userEntity.setFirstName("John");
        userEntity.setLastName("Smith");
        userEntity.setEmailAddress("john.smith@example.com");
        userEntity.setAuthenticators(Collections.emptyList());
        userEntity.setAuthorities(Collections.singletonList(new AuthorityEntity(0, "SINGLE_FACTOR_AUTHN_ALLOWED")));

        when(profileAppService.update(anyInt(), any())).thenReturn(userEntity);

        //When
        mvc.perform(
                put("/api/profile")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userUpdateForm))
                        .with(SecurityMockMvcRequestPostProcessors.csrf())
        )
                //Then
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(1)))
                .andExpect(jsonPath("$.userHandle", is(Base64UrlUtil.encodeToString(userHandle))))
                .andExpect(jsonPath("$.firstName", is("John")))
                .andExpect(jsonPath("$.lastName", is("Smith")))
                .andExpect(jsonPath("$.emailAddress", is("john.smith@example.com")))
                .andExpect(jsonPath("$.authenticators", is(empty())))
                .andExpect(jsonPath("$.singleFactorAuthenticationAllowed", is(true)))
        ;
        verify(profileAppService).update(anyInt(), any());
    }

    @Test
    @WithMockWebAuthnUser(id = 1, firstName = "John", lastName = "Doe", emailAddress = "john.doe@example.com", authorities = {"ROLE_USER"}, authenticators = {})
    public void delete_test() throws Exception {

        //When
        mvc.perform(
                delete("/api/profile")
                        .with(SecurityMockMvcRequestPostProcessors.csrf())
        )
                //Then
                .andExpect(status().isOk());
        verify(profileAppService).delete(anyInt());
    }

}
