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

package com.webauthn4j.springframework.security;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.util.internal.ExceptionUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;


public class WebAuthnRegistrationRequestValidator {

    // ~ Instance fields
    // ================================================================================================
    private final WebAuthnManager webAuthnManager;
    private final ServerPropertyProvider serverPropertyProvider;

    // ~ Constructors
    // ===================================================================================================

    /**
     * Constructor
     *
     * @param webAuthnManager        validator for {@link WebAuthnManager}
     * @param serverPropertyProvider provider for {@link ServerProperty}
     */
    public WebAuthnRegistrationRequestValidator(WebAuthnManager webAuthnManager, ServerPropertyProvider serverPropertyProvider) {

        Assert.notNull(webAuthnManager, "webAuthnManager must not be null");
        Assert.notNull(serverPropertyProvider, "serverPropertyProvider must not be null");

        this.webAuthnManager = webAuthnManager;
        this.serverPropertyProvider = serverPropertyProvider;
    }

    // ~ Methods
    // ========================================================================================================

    public WebAuthnRegistrationRequestValidationResponse validate(HttpServletRequest httpServletRequest,
                                                                  String clientDataBase64url,
                                                                  String attestationObjectBase64url,
                                                                  Set<String> transports,
                                                                  String clientExtensionsJSON
    ) {
        Assert.notNull(httpServletRequest, "httpServletRequest must not be null");
        Assert.hasText(clientDataBase64url, "clientDataBase64url must have text");
        Assert.hasText(attestationObjectBase64url, "attestationObjectBase64url must have text");
        if (transports != null) {
            transports.forEach(transport -> Assert.hasText(transport, "each transport must have text"));
        }

        RegistrationRequest webAuthnRegistrationRequest =
                createRegistrationRequest(clientDataBase64url, attestationObjectBase64url, transports, clientExtensionsJSON);
        RegistrationParameters webAuthnRegistrationParameters =
                createRegistrationParameters(httpServletRequest);

        try {
            RegistrationData response = webAuthnManager.validate(webAuthnRegistrationRequest, webAuthnRegistrationParameters);
            return new WebAuthnRegistrationRequestValidationResponse(
                    response.getCollectedClientData(),
                    response.getAttestationObject(),
                    response.getClientExtensions(),
                    response.getTransports());
        } catch (WebAuthnException e) {
            throw ExceptionUtil.wrapWithAuthenticationException(e);
        }
    }

    RegistrationRequest createRegistrationRequest(String clientDataBase64,
                                                  String attestationObjectBase64,
                                                  Set<String> transports,
                                                  String clientExtensionsJSON) {

        byte[] clientDataBytes = Base64UrlUtil.decode(clientDataBase64);
        byte[] attestationObjectBytes = Base64UrlUtil.decode(attestationObjectBase64);

        return new RegistrationRequest(
                attestationObjectBytes,
                clientDataBytes,
                clientExtensionsJSON,
                transports
        );
    }

    RegistrationParameters createRegistrationParameters(HttpServletRequest request) {
        ServerProperty serverProperty = serverPropertyProvider.provide(request);
        return new RegistrationParameters(
                serverProperty,
                null,
                false,
                false
        );
    }

}
