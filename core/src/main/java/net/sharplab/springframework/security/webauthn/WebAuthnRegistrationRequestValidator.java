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

package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.response.WebAuthnRegistrationContext;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import net.sharplab.springframework.security.webauthn.util.ExceptionUtil;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.List;


public class WebAuthnRegistrationRequestValidator {

    //~ Instance fields
    // ================================================================================================
    private WebAuthnRegistrationContextValidator registrationContextValidator;
    private ServerPropertyProvider serverPropertyProvider;

    private boolean userVerificationRequired;
    private List<String> expectedRegistrationExtensionIds;

    /**
     * Constructor
     *
     * @param registrationContextValidator validator for {@link WebAuthnRegistrationContext}
     * @param serverPropertyProvider       provider for {@link ServerProperty}
     */
    public WebAuthnRegistrationRequestValidator(WebAuthnRegistrationContextValidator registrationContextValidator, ServerPropertyProvider serverPropertyProvider) {
        this.registrationContextValidator = registrationContextValidator;
        this.serverPropertyProvider = serverPropertyProvider;
    }

    public WebAuthnRegistrationRequestValidationResponse validate(HttpServletRequest httpServletRequest,
                                                                  String clientDataBase64url,
                                                                  String attestationObjectBase64url,
                                                                  String clientExtensionsJSON
    ) {
        Assert.notNull(httpServletRequest, "httpServletRequest must not be null");
        Assert.hasText(clientDataBase64url, "clientDataBase64url must have text");
        Assert.hasText(attestationObjectBase64url, "attestationObjectBase64url must have text");

        WebAuthnRegistrationContext registrationContext = createRegistrationContext(httpServletRequest, clientDataBase64url, attestationObjectBase64url, clientExtensionsJSON);
        WebAuthnRegistrationContextValidationResponse response = registrationContextValidator.validate(registrationContext);

        try {
            return new WebAuthnRegistrationRequestValidationResponse(
                    response.getCollectedClientData(),
                    response.getAttestationObject(),
                    response.getRegistrationExtensionsClientOutputs());
        } catch (RuntimeException e) {
            throw ExceptionUtil.wrapWithAuthenticationException(e);
        }
    }

    WebAuthnRegistrationContext createRegistrationContext(HttpServletRequest request,
                                                          String clientDataBase64,
                                                          String attestationObjectBase64,
                                                          String clientExtensionsJSON) {

        byte[] clientDataBytes = Base64UrlUtil.decode(clientDataBase64);
        byte[] attestationObjectBytes = Base64UrlUtil.decode(attestationObjectBase64);
        ServerProperty serverProperty = serverPropertyProvider.provide(request);

        return new WebAuthnRegistrationContext(
                clientDataBytes,
                attestationObjectBytes,
                clientExtensionsJSON,
                serverProperty,
                userVerificationRequired,
                expectedRegistrationExtensionIds);
    }

    /**
     * Check if user verification is required
     *
     * @return true if user verification is required
     */
    public boolean isUserVerificationRequired() {
        return userVerificationRequired;
    }

    /**
     * Set whether user verification is required
     *
     * @param userVerificationRequired true if user verification is required
     */
    public void setUserVerificationRequired(boolean userVerificationRequired) {
        this.userVerificationRequired = userVerificationRequired;
    }

    public List<String> getExpectedRegistrationExtensionIds() {
        return expectedRegistrationExtensionIds;
    }

    public void setExpectedRegistrationExtensionIds(List<String> expectedRegistrationExtensionIds) {
        Assert.notNull(expectedRegistrationExtensionIds, "expectedRegistrationExtensionIds must not be null");
        this.expectedRegistrationExtensionIds = expectedRegistrationExtensionIds;
    }
}
