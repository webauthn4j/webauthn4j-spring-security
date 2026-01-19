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

package com.webauthn4j.springframework.security.util;

import com.webauthn4j.springframework.security.exception.*;
import com.webauthn4j.springframework.security.util.internal.ExceptionUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationServiceException;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class ExceptionUtilTest {

    @Test
    public void wrapWithAuthenticationException_test() {

        Map<WebAuthnException, Class<?>> map = new HashMap<>();
        map.put(new com.webauthn4j.verifier.exception.BadAaguidException("dummy"), BadAaguidException.class);
        map.put(new com.webauthn4j.verifier.exception.BadAlgorithmException("dummy"), BadAlgorithmException.class);
        map.put(new com.webauthn4j.verifier.exception.BadAttestationStatementException("dummy"), BadAttestationStatementException.class);
        map.put(new com.webauthn4j.verifier.exception.KeyDescriptionValidationException("dummy"), KeyDescriptionValidationException.class);
        map.put(new com.webauthn4j.verifier.exception.BadChallengeException("dummy"), BadChallengeException.class);
        map.put(new com.webauthn4j.verifier.exception.BadOriginException("dummy"), BadOriginException.class);
        map.put(new com.webauthn4j.verifier.exception.BadRpIdException("dummy"), BadRpIdException.class);
        map.put(new com.webauthn4j.verifier.exception.BadSignatureException("dummy"), BadSignatureException.class);
        map.put(new com.webauthn4j.metadata.exception.BadStatusException("dummy"), BadStatusException.class);
        map.put(new com.webauthn4j.verifier.exception.CertificateException("dummy"), CertificateException.class);
        map.put(new com.webauthn4j.verifier.exception.ConstraintViolationException("dummy"), ConstraintViolationException.class);
        map.put(new com.webauthn4j.verifier.exception.MaliciousCounterValueException("dummy"), MaliciousCounterValueException.class);
        map.put(new com.webauthn4j.verifier.exception.InconsistentClientDataTypeException("dummy"), InconsistentClientDataTypeException.class);
        map.put(new com.webauthn4j.verifier.exception.MissingChallengeException("dummy"), MissingChallengeException.class);
        map.put(new com.webauthn4j.verifier.exception.PublicKeyMismatchException("dummy"), PublicKeyMismatchException.class);
        map.put(new com.webauthn4j.verifier.exception.SelfAttestationProhibitedException("dummy"), SelfAttestationProhibitedException.class);
        map.put(new com.webauthn4j.verifier.exception.TokenBindingException("dummy"), TokenBindingException.class);
        map.put(new com.webauthn4j.verifier.exception.TrustAnchorNotFoundException("dummy"), TrustAnchorNotFoundException.class);
        map.put(new com.webauthn4j.verifier.exception.UnexpectedExtensionException("dummy"), UnexpectedExtensionException.class);
        map.put(new com.webauthn4j.verifier.exception.UserNotPresentException("dummy"), UserNotPresentException.class);
        map.put(new com.webauthn4j.verifier.exception.UserNotVerifiedException("dummy"), UserNotVerifiedException.class);
        map.put(new ExceptionUtilTest.UnknownValidationException("dummy"), ValidationException.class);
        map.put(new com.webauthn4j.converter.exception.DataConversionException("dummy"), DataConversionException.class);
        map.put(new com.webauthn4j.util.exception.WebAuthnException("dummy"), AuthenticationServiceException.class);

        for (Map.Entry<WebAuthnException, Class<?>> entry : map.entrySet()) {
            assertThat(ExceptionUtil.wrapWithAuthenticationException(entry.getKey())).isInstanceOf(entry.getValue());
        }
    }

    static class UnknownValidationException extends com.webauthn4j.verifier.exception.VerificationException {

        UnknownValidationException(String message) {
            super(message);
        }
    }
}
