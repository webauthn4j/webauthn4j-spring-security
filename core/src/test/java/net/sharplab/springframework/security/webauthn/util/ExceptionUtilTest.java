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

package net.sharplab.springframework.security.webauthn.util;

import net.sharplab.springframework.security.webauthn.exception.*;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationServiceException;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class ExceptionUtilTest {

    @Test
    public void wrapWithAuthenticationException_test() {

        Map<RuntimeException, Class> map = new HashMap<>();
        map.put(new com.webauthn4j.validator.exception.BadAlgorithmException("dummy"), BadAlgorithmException.class);
        map.put(new com.webauthn4j.validator.exception.BadAttestationStatementException("dummy"), BadAttestationStatementException.class);
        map.put(new com.webauthn4j.validator.exception.BadChallengeException("dummy"), BadChallengeException.class);
        map.put(new com.webauthn4j.validator.exception.BadOriginException("dummy"), BadOriginException.class);
        map.put(new com.webauthn4j.validator.exception.BadRpIdException("dummy"), BadRpIdException.class);
        map.put(new com.webauthn4j.validator.exception.BadSignatureException("dummy"), BadSignatureException.class);
        map.put(new com.webauthn4j.validator.exception.CertificateException("dummy"), CertificateException.class);
        map.put(new com.webauthn4j.validator.exception.ConstraintViolationException("dummy"), ConstraintViolationException.class);
        map.put(new com.webauthn4j.validator.exception.MaliciousCounterValueException("dummy"), MaliciousCounterValueException.class);
        map.put(new com.webauthn4j.validator.exception.MaliciousDataException("dummy"), MaliciousDataException.class);
        map.put(new com.webauthn4j.validator.exception.MissingChallengeException("dummy"), MissingChallengeException.class);
        map.put(new com.webauthn4j.validator.exception.SelfAttestationProhibitedException("dummy"), SelfAttestationProhibitedException.class);
        map.put(new com.webauthn4j.validator.exception.TokenBindingException("dummy"), TokenBindingException.class);
        map.put(new com.webauthn4j.validator.exception.UnexpectedExtensionException("dummy"), UnexpectedExtensionException.class);
        map.put(new com.webauthn4j.validator.exception.UserNotPresentException("dummy"), UserNotPresentException.class);
        map.put(new com.webauthn4j.validator.exception.UserNotVerifiedException("dummy"), UserNotVerifiedException.class);
        map.put(new ExceptionUtilTest.UnknownValidationException("dummy"), AuthenticationServiceException.class);
        map.put(new RuntimeException("dummy"), RuntimeException.class);

        for (Map.Entry<RuntimeException, Class> entry : map.entrySet()) {
            assertThat(ExceptionUtil.wrapWithAuthenticationException(entry.getKey())).isInstanceOf(entry.getValue());
        }
    }

    static class UnknownValidationException extends com.webauthn4j.validator.exception.ValidationException {

        UnknownValidationException(String message) {
            super(message);
        }
    }
}
