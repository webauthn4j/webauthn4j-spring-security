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

package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import net.sharplab.springframework.security.webauthn.server.ServerPropertyProvider;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Test for WebAuthnRegistrationContextValidator
 */
public class WebAuthnRegistrationRequestValidatorTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @Mock
    WebAuthnRegistrationContextValidator registrationContextValidator;

    @Mock
    ServerPropertyProvider serverPropertyProvider;


    @Test
    public void validate_test() {
        WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(
                registrationContextValidator, serverPropertyProvider
        );
        target.setUserVerificationRequired(true);

        ServerProperty serverProperty = mock(ServerProperty.class);
        when(serverPropertyProvider.provide(any())).thenReturn(serverProperty);

        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setScheme("https");
        mockHttpServletRequest.setServerName("example.com");
        mockHttpServletRequest.setServerPort(443);
        String clientDataBase64 = "clientDataBase64";
        String attestationObjectBase64 = "attestationObjectBase64";
        String clientExtensionsJSON = null;

        target.validate(mockHttpServletRequest, null, clientDataBase64, attestationObjectBase64, clientExtensionsJSON);

        ArgumentCaptor<WebAuthnRegistrationContext> argumentCaptor = ArgumentCaptor.forClass(WebAuthnRegistrationContext.class);
        verify(registrationContextValidator).validate(argumentCaptor.capture());
        WebAuthnRegistrationContext registrationContext = argumentCaptor.getValue();

        assertThat(registrationContext.getClientDataJSON()).isEqualTo(Base64UrlUtil.decode(clientDataBase64));
        assertThat(registrationContext.getAttestationObject()).isEqualTo(Base64UrlUtil.decode(attestationObjectBase64));
        assertThat(registrationContext.getClientExtensionsJSON()).isEqualTo(clientExtensionsJSON);
        assertThat(registrationContext.getServerProperty()).isEqualTo(serverProperty);
        assertThat(registrationContext.isUserVerificationRequired()).isEqualTo(target.isUserVerificationRequired());
        assertThat(registrationContext.getExpectedExtensionIds()).isEqualTo(target.getExpectedRegistrationExtensionIds());
    }

    @Test
    public void getter_setter_test() {
        WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(
                registrationContextValidator, serverPropertyProvider
        );

        target.setUserVerificationRequired(true);
        assertThat(target.isUserVerificationRequired()).isTrue();
        target.setExpectedRegistrationExtensionIds(Collections.singletonList("appId"));
        assertThat(target.getExpectedRegistrationExtensionIds()).containsExactly("appId");

    }

}
