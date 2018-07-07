/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.sample.app.web;

import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.List;

public class ProfileForm {

    /**
     * userHandle
     */
    @NotNull //TODO
    private String userHandle;

    /**
     * first name
     */
    @NotEmpty
    private String firstName;

    /**
     * last name
     */
    @NotEmpty
    private String lastName;

    /**
     * email address
     */
    @NotEmpty
    @Email
    private String emailAddress;

    /**
     * require residentKey
     */
    private boolean requireResidentKey;

    /**
     * authenticators
     */
    @Valid
    private List<AuthenticatorUpdateForm> authenticators;

    /**
     * new authenticators
     */
    @Valid
    private List<AuthenticatorCreateForm> newAuthenticators;


    /**
     * <code>true</code> if password authentication is allowed
     */
    private boolean singleFactorAuthenticationAllowed;

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

    public boolean isRequireResidentKey() {
        return requireResidentKey;
    }

    public void setRequireResidentKey(boolean requireResidentKey) {
        this.requireResidentKey = requireResidentKey;
    }

    public List<AuthenticatorUpdateForm> getAuthenticators() {
        return authenticators;
    }

    public void setAuthenticators(List<AuthenticatorUpdateForm> authenticators) {
        this.authenticators = authenticators;
    }

    public List<AuthenticatorCreateForm> getNewAuthenticators() {
        return newAuthenticators;
    }

    public void setNewAuthenticators(List<AuthenticatorCreateForm> newAuthenticators) {
        this.newAuthenticators = newAuthenticators;
    }

    public boolean isSingleFactorAuthenticationAllowed() {
        return singleFactorAuthenticationAllowed;
    }

    public void setSingleFactorAuthenticationAllowed(boolean singleFactorAuthenticationAllowed) {
        this.singleFactorAuthenticationAllowed = singleFactorAuthenticationAllowed;
    }
}
