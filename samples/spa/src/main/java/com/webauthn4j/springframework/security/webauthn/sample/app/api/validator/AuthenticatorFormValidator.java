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

package com.webauthn4j.springframework.security.webauthn.sample.app.api.validator;

import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.webauthn.sample.app.api.AuthenticatorForm;
import com.webauthn4j.validator.exception.ValidationException;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class AuthenticatorFormValidator {

    private static final String NOT_NULL = "not.null";

    private final WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator;

    public AuthenticatorFormValidator(WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator) {
        this.webAuthnRegistrationRequestValidator = webAuthnRegistrationRequestValidator;
    }

    public void validate(HttpServletRequest request, AuthenticatorForm form, Errors errors) {
        if (form.getId() == null) {
            if (form.getCredentialId() == null) {
                errors.rejectValue("credentialId", NOT_NULL);
            }
            if (form.getAttestationObject() == null) {
                errors.rejectValue("attestationObject", NOT_NULL);
            }
            if (form.getClientData() == null) {
                errors.rejectValue("clientData", NOT_NULL);
            }
            if (form.getClientExtensionsJSON() == null) {
                errors.rejectValue("clientExtensionsJSON", NOT_NULL);
            }
            try {
                webAuthnRegistrationRequestValidator.validate(
                        request,
                        form.getClientData().getClientDataBase64(),
                        form.getAttestationObject().getAttestationObjectBase64(),
                        form.getTransports(),
                        form.getClientExtensionsJSON());
            } catch (ValidationException exception) {
                errors.reject("e.AuthenticatorFormValidator.invalidAuthenticator", "AuthenticatorEntity is invalid.");
            }

        }
    }
}
