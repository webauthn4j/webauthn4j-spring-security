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
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.springframework.security.exception.BadAttestationStatementException;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Test for WebAuthnRegistrationRequestValidator
 */
public class WebAuthnRegistrationRequestValidatorTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @Mock
    private WebAuthnManager webAuthnManager;

    @Mock
    private ServerPropertyProvider serverPropertyProvider;


    @Test
    public void verify_test() {
        WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(
                webAuthnManager, serverPropertyProvider
        );

        ServerProperty serverProperty = mock(ServerProperty.class);
        when(serverPropertyProvider.provide(any())).thenReturn(serverProperty);

        CollectedClientData collectedClientData = mock(CollectedClientData.class);
        AttestationObject attestationObject = mock(AttestationObject.class);
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensionOutputs = new AuthenticationExtensionsClientOutputs<>();
        when(webAuthnManager.verify(any(RegistrationRequest.class), any(RegistrationParameters.class))).thenReturn(
                new RegistrationData(attestationObject, null, collectedClientData, null, clientExtensionOutputs, null));

        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setScheme("https");
        mockHttpServletRequest.setServerName("example.com");
        mockHttpServletRequest.setServerPort(443);
        String clientDataBase64 = "clientDataBase64";
        String attestationObjectBase64 = "attestationObjectBase64";
        Set<String> transports = Collections.emptySet();
        String clientExtensionsJSON = "clientExtensionsJSON";

        target.validate(mockHttpServletRequest, clientDataBase64, attestationObjectBase64, transports, clientExtensionsJSON);

        ArgumentCaptor<RegistrationRequest> registrationRequestArgumentCaptor = ArgumentCaptor.forClass(RegistrationRequest.class);
        ArgumentCaptor<RegistrationParameters> registrationParametersArgumentCaptor = ArgumentCaptor.forClass(RegistrationParameters.class);
        verify(webAuthnManager).verify(registrationRequestArgumentCaptor.capture(), registrationParametersArgumentCaptor.capture());
        RegistrationRequest registrationRequest = registrationRequestArgumentCaptor.getValue();
        RegistrationParameters registrationParameters = registrationParametersArgumentCaptor.getValue();

        assertThat(registrationRequest.getClientDataJSON()).isEqualTo(Base64UrlUtil.decode(clientDataBase64));
        assertThat(registrationRequest.getAttestationObject()).isEqualTo(Base64UrlUtil.decode(attestationObjectBase64));
        assertThat(registrationRequest.getClientExtensionsJSON()).isEqualTo(clientExtensionsJSON);
        assertThat(registrationParameters.getServerProperty()).isEqualTo(serverProperty);
    }

    @Test
    public void validate_with_transports_null_test() {
        WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(
                webAuthnManager, serverPropertyProvider
        );

        ServerProperty serverProperty = mock(ServerProperty.class);
        when(serverPropertyProvider.provide(any())).thenReturn(serverProperty);

        CollectedClientData collectedClientData = mock(CollectedClientData.class);
        AttestationObject attestationObject = mock(AttestationObject.class);
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensionOutputs = new AuthenticationExtensionsClientOutputs<>();
        when(webAuthnManager.verify(any(RegistrationRequest.class), any(RegistrationParameters.class))).thenReturn(
                new RegistrationData(attestationObject, null, collectedClientData, null, clientExtensionOutputs, null));

        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setScheme("https");
        mockHttpServletRequest.setServerName("example.com");
        mockHttpServletRequest.setServerPort(443);
        String clientDataBase64 = "clientDataBase64";
        String attestationObjectBase64 = "attestationObjectBase64";
        String clientExtensionsJSON = "clientExtensionsJSON";

        target.validate(mockHttpServletRequest, clientDataBase64, attestationObjectBase64, null, clientExtensionsJSON);

        ArgumentCaptor<RegistrationRequest> registrationRequestArgumentCaptor = ArgumentCaptor.forClass(RegistrationRequest.class);
        ArgumentCaptor<RegistrationParameters> registrationParametersArgumentCaptor = ArgumentCaptor.forClass(RegistrationParameters.class);
        verify(webAuthnManager).verify(registrationRequestArgumentCaptor.capture(), registrationParametersArgumentCaptor.capture());
        RegistrationRequest registrationRequest = registrationRequestArgumentCaptor.getValue();
        RegistrationParameters registrationParameters = registrationParametersArgumentCaptor.getValue();

        assertThat(registrationRequest.getClientDataJSON()).isEqualTo(Base64UrlUtil.decode(clientDataBase64));
        assertThat(registrationRequest.getAttestationObject()).isEqualTo(Base64UrlUtil.decode(attestationObjectBase64));
        assertThat(registrationRequest.getClientExtensionsJSON()).isEqualTo(clientExtensionsJSON);
        assertThat(registrationParameters.getServerProperty()).isEqualTo(serverProperty);
    }

    @Test(expected = BadAttestationStatementException.class)
    public void validate_caught_exception_test() {

        ServerProperty serverProperty = mock(ServerProperty.class);
        when(serverPropertyProvider.provide(any())).thenReturn(serverProperty);

        WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(
                webAuthnManager, serverPropertyProvider
        );
        when(webAuthnManager.verify(any(RegistrationRequest.class), any(RegistrationParameters.class))).thenThrow(new com.webauthn4j.verifier.exception.BadAttestationStatementException("dummy"));

        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setScheme("https");
        mockHttpServletRequest.setServerName("example.com");
        mockHttpServletRequest.setServerPort(443);
        String clientDataBase64 = "clientDataBase64";
        String attestationObjectBase64 = "attestationObjectBase64";
        Set<String> transports = Collections.emptySet();
        String clientExtensionsJSON = "clientExtensionsJSON";

        target.validate(mockHttpServletRequest, clientDataBase64, attestationObjectBase64, transports, clientExtensionsJSON);

    }
}
