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

package com.webauthn4j.springframework.security.webauthn.sample.app.util;

import com.webauthn4j.springframework.security.webauthn.sample.app.api.AuthenticatorForm;
import com.webauthn4j.springframework.security.webauthn.sample.app.api.ProfileCreateForm;
import com.webauthn4j.springframework.security.webauthn.sample.app.api.ProfileForm;
import com.webauthn4j.springframework.security.webauthn.sample.app.api.ProfileUpdateForm;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.entity.UserEntity;
import com.webauthn4j.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
public class AppSpecificMapper {

    @Autowired
    PasswordEncoder passwordEncoder;

    public ProfileForm mapToProfileForm(UserEntity userEntity) {
        ProfileForm profileForm = new ProfileForm();
        profileForm.setId(userEntity.getId());
        profileForm.setUserHandle(mapToBase64Url(userEntity.getUserHandle()));
        profileForm.setFirstName(userEntity.getFirstName());
        profileForm.setLastName(userEntity.getLastName());
        profileForm.setEmailAddress(userEntity.getEmailAddress());

        // authenticators
        profileForm.setAuthenticators(new ArrayList<>());
        mapToAuthenticatorFormList(userEntity.getAuthenticators(), profileForm.getAuthenticators());
        profileForm.setSingleFactorAuthenticationAllowed(userEntity.getAuthorities().stream().anyMatch(authorityEntity -> authorityEntity.getAuthority().equals("SINGLE_FACTOR_AUTHN_ALLOWED")));

        return profileForm;
    }

    private AuthenticatorEntity mapForCreate(AuthenticatorForm authenticatorForm) {
        AuthenticatorEntity authenticatorEntity = new AuthenticatorEntity();
        authenticatorEntity.setName(authenticatorForm.getName());
        authenticatorEntity.setAttestationStatement(authenticatorForm.getAttestationObject().getAttestationObject().getAttestationStatement());
        authenticatorEntity.setAttestedCredentialData(authenticatorForm.getAttestationObject().getAttestationObject().getAuthenticatorData().getAttestedCredentialData());
        return authenticatorEntity;
    }

    private AuthenticatorEntity mapForUpdate(AuthenticatorForm authenticatorForm, AuthenticatorEntity authenticatorEntity) {
        authenticatorEntity.setName(authenticatorForm.getName());
        // attestationStatement and attestedCredentialData won't be updated
        return authenticatorEntity;
    }

    private AuthenticatorForm mapToAuthenticatorForm(AuthenticatorEntity authenticatorEntity) {
        AuthenticatorForm authenticatorForm = new AuthenticatorForm();
        authenticatorForm.setId(authenticatorEntity.getId());
        authenticatorForm.setCredentialId(Base64UrlUtil.encodeToString(authenticatorEntity.getAttestedCredentialData().getCredentialId()));
        authenticatorForm.setName(authenticatorEntity.getName());
        return authenticatorForm;
    }

    public UserEntity mapForCreate(ProfileCreateForm profileCreateForm) {
        UserEntity userEntity = new UserEntity();
        userEntity.setId(null);
        userEntity.setUserHandle(mapFromBase64Url(profileCreateForm.getUserHandle()));
        userEntity.setFirstName(profileCreateForm.getFirstName());
        userEntity.setLastName(profileCreateForm.getLastName());
        userEntity.setEmailAddress(profileCreateForm.getEmailAddress());
        userEntity.setPassword(passwordEncoder.encode(profileCreateForm.getPassword()));

        // authenticators
        userEntity.setAuthenticators(new ArrayList<>());
        mapToAuthenticatorListForCreate(profileCreateForm.getAuthenticators(), userEntity.getAuthenticators());
        userEntity.getAuthenticators().forEach(authenticatorEntity -> authenticatorEntity.setUser(userEntity));

        // authorities
        List<AuthorityEntity> authorities = new ArrayList<>();
        if(profileCreateForm.isSingleFactorAuthenticationAllowed() == true){
            authorities.add(new AuthorityEntity(null, "SINGLE_FACTOR_AUTHN_ALLOWED"));
        }
        userEntity.setAuthorities(authorities);

        return userEntity;
    }

    public UserEntity mapForUpdate(ProfileUpdateForm profileUpdateForm, UserEntity userEntity) {
        userEntity.setUserHandle(mapFromBase64Url(profileUpdateForm.getUserHandle()));
        userEntity.setFirstName(profileUpdateForm.getFirstName());
        userEntity.setLastName(profileUpdateForm.getLastName());
        userEntity.setEmailAddress(profileUpdateForm.getEmailAddress());

        // authenticators
        List<AuthenticatorForm> authenticatorForms = profileUpdateForm.getAuthenticators();
        mapToAuthenticatorListForUpdate(authenticatorForms, userEntity.getAuthenticators());
        userEntity.getAuthenticators().forEach(authenticatorEntity -> authenticatorEntity.setUser(userEntity));

        // authorities
        List<AuthorityEntity> authorities = userEntity.getAuthorities();
        if(profileUpdateForm.isSingleFactorAuthenticationAllowed() == true){
            if(authorities.stream().anyMatch(authorityEntity -> authorityEntity.getAuthority().equals("SINGLE_FACTOR_AUTHN_ALLOWED"))){
                //nop
            }
            else {
                authorities.add(new AuthorityEntity(null, "SINGLE_FACTOR_AUTHN_ALLOWED"));
            }
        }
        else {
            authorities.clear();
        }

        return userEntity;
    }

    private List<AuthenticatorForm> mapToAuthenticatorFormList(List<AuthenticatorEntity> authenticatorEntities, List<AuthenticatorForm> authenticatorForms) {
        for (AuthenticatorEntity authenticatorEntity : authenticatorEntities) {
            authenticatorForms.add(mapToAuthenticatorForm(authenticatorEntity));
        }
        return authenticatorForms;
    }

    private List<AuthenticatorEntity> mapToAuthenticatorListForCreate(List<AuthenticatorForm> authenticatorForms, List<AuthenticatorEntity> authenticatorEntities) {
        for (AuthenticatorForm authenticatorForm : authenticatorForms) {
            authenticatorEntities.add(mapForCreate(authenticatorForm));
        }
        return authenticatorEntities;
    }

    private List<AuthenticatorEntity> mapToAuthenticatorListForUpdate(List<AuthenticatorForm> authenticatorForms, List<AuthenticatorEntity> authenticatorEntities) {
        int[] sortedKeptIds = authenticatorForms.stream()
                .filter(authenticator -> authenticator.getId() != null)
                .mapToInt(AuthenticatorForm::getId).sorted().toArray();
        for (AuthenticatorForm authenticatorForm : authenticatorForms) {
            Integer id = authenticatorForm.getId();
            // addExtension new authenticator
            if (id == null) {
                authenticatorEntities.add(mapForCreate(authenticatorForm));
            }
            // update existing authenticator
            else {
                AuthenticatorEntity correspondingAuthenticatorEntity =
                        authenticatorEntities.stream().filter(item -> item.getId().equals(id))
                                .findFirst().orElseThrow(() -> new WebAuthnSampleEntityNotFoundException("Corresponding authenticator is not found."));
                mapForUpdate(authenticatorForm, correspondingAuthenticatorEntity);
            }

        }
        // delete authenticatorEntities if it is not included in authenticatorForms
        authenticatorEntities.removeIf(authenticatorEntity -> {
            Integer id = authenticatorEntity.getId();
            if (id == null) {
                return false;
            }
            return Arrays.binarySearch(sortedKeptIds, id) < 0;
        });
        return authenticatorEntities;
    }

    public byte[] mapFromBase64Url(String base64url) {
        return Base64UrlUtil.decode(base64url);
    }

    public String mapToBase64Url(byte[] bytes) {
        return Base64UrlUtil.encodeToString(bytes);
    }


}
