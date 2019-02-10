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

package integration.component;

import com.webauthn4j.request.*;
import com.webauthn4j.response.AuthenticatorAttestationResponse;
import com.webauthn4j.response.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.response.client.Origin;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.authenticator.model.WebAuthnModelAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidationResponse;
import net.sharplab.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test for WebAuthnRegistrationContextValidator
 */
public class RegistrationValidationTest {

    String rpId = "example.com";
    Challenge challenge = new DefaultChallenge();
    private Origin origin = new Origin("http://localhost");
    private WebAuthnModelAuthenticatorAdaptor webAuthnModelAuthenticatorAdaptor = new WebAuthnModelAuthenticatorAdaptor();
    private ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnModelAuthenticatorAdaptor);
    private ServerPropertyProvider serverPropertyProvider = mock(ServerPropertyProvider.class);
    private WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(
            WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator(), serverPropertyProvider
    );

    @Test
    public void validate_test() {
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        when(serverPropertyProvider.provide(any())).thenReturn(serverProperty);


        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
                new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity();

        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                publicKeyCredentialUserEntity,
                challenge,
                Collections.singletonList(publicKeyCredentialParameters),
                null,
                null,
                authenticatorSelectionCriteria,
                AttestationConveyancePreference.NONE,
                null
        );

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();

        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setScheme("https");
        mockHttpServletRequest.setServerName("example.com");
        mockHttpServletRequest.setServerPort(443);

        String clientDataBase64 = Base64UrlUtil.encodeToString(registrationRequest.getClientDataJSON());
        String attestationObjectBase64 = Base64UrlUtil.encodeToString(registrationRequest.getAttestationObject());
        String clientExtensionsJSON = null;

        WebAuthnRegistrationRequestValidationResponse response
                = target.validate(mockHttpServletRequest, clientDataBase64, attestationObjectBase64, clientExtensionsJSON);

        assertThat(response.getAttestationObject()).isNotNull();
        assertThat(response.getCollectedClientData()).isNotNull();
        assertThat(response.getRegistrationExtensionsClientOutputs()).isNull();
    }

}
