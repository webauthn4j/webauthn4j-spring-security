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

package com.webauthn4j.springframework.security.webauthn.sample.app.api.validator.spring;

import com.webauthn4j.springframework.security.webauthn.sample.app.api.AuthenticatorForm;
import com.webauthn4j.springframework.security.webauthn.sample.app.api.ProfileCreateForm;
import com.webauthn4j.springframework.security.webauthn.sample.app.api.validator.AuthenticatorFormValidator;
import com.webauthn4j.validator.exception.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class ProfileCreateFormValidator implements Validator {

    @Autowired
    private HttpServletRequest request;

    private final AuthenticatorFormValidator authenticatorFormValidator;

    public ProfileCreateFormValidator(AuthenticatorFormValidator authenticatorFormValidator) {
        this.authenticatorFormValidator = authenticatorFormValidator;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return ProfileCreateForm.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        ProfileCreateForm form = (ProfileCreateForm) target;

        if (form.getAuthenticators() == null || form.getAuthenticators().isEmpty()) {

            if (!form.isSingleFactorAuthenticationAllowed()) {
                errors.rejectValue("authenticators",
                        "e.ProfileCreateFormValidator.noAuthenticator",
                        "To disable password authentication, at least one authenticator must be registered.");
            }
        } else {
            for (AuthenticatorForm authenticator : form.getAuthenticators()) {
                try {
                    authenticatorFormValidator.validate(request, authenticator, errors);
                } catch (ValidationException exception) {
                    errors.rejectValue("authenticators", "e.ProfileCreateFormValidator.invalidAuthenticator", "AuthenticatorEntity is invalid.");
                }
            }
        }
    }
}
