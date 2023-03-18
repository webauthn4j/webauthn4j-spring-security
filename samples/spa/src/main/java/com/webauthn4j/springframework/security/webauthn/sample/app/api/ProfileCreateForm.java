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

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public class ProfileCreateForm {

    @NotEmpty
    private String userHandle;

    @NotEmpty
    private String firstName;

    @NotEmpty
    private String lastName;

    @NotEmpty
    @Email
    private String emailAddress;

    @NotEmpty
    private String password;

    @Valid
    private List<AuthenticatorForm> authenticators;

    @NotNull
    private Boolean singleFactorAuthenticationAllowed;

    public String getUserHandle() {
        return userHandle;
    }

    public void setUserHandle(String userHandle) {
        this.userHandle = userHandle;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<AuthenticatorForm> getAuthenticators() {
        return authenticators;
    }

    public void setAuthenticators(List<AuthenticatorForm> authenticators) {
        this.authenticators = authenticators;
    }

    public Boolean isSingleFactorAuthenticationAllowed() {
        return singleFactorAuthenticationAllowed;
    }

    public void setSingleFactorAuthenticationAllowed(Boolean singleFactorAuthenticationAllowed) {
        this.singleFactorAuthenticationAllowed = singleFactorAuthenticationAllowed;
    }
}
