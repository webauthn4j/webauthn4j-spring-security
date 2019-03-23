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
import org.springframework.security.authentication.AuthenticationServiceException;

public class ExceptionUtil {

    private ExceptionUtil() {
    }

    @SuppressWarnings("squid:S3776")
    public static RuntimeException wrapWithAuthenticationException(RuntimeException e) {
        if (e instanceof com.webauthn4j.validator.exception.BadAlgorithmException) {
            return new BadAlgorithmException("Bad algorithm", e);
        } else if (e instanceof com.webauthn4j.validator.exception.BadAttestationStatementException) {
            return new BadAttestationStatementException("Bad attestation statement", e);
        } else if (e instanceof com.webauthn4j.validator.exception.BadChallengeException) {
            return new BadChallengeException("Bad challenge", e);
        } else if (e instanceof com.webauthn4j.validator.exception.BadOriginException) {
            return new BadOriginException("Bad origin", e);
        } else if (e instanceof com.webauthn4j.validator.exception.BadRpIdException) {
            return new BadRpIdException("Bad rpId", e);
        } else if (e instanceof com.webauthn4j.validator.exception.BadSignatureException) {
            return new BadSignatureException("Bad signature", e);
        } else if (e instanceof com.webauthn4j.validator.exception.CertificateException) {
            return new CertificateException("Certificate error", e);
        } else if (e instanceof com.webauthn4j.validator.exception.ConstraintViolationException) {
            return new ConstraintViolationException("Constraint violation error", e);
        } else if (e instanceof com.webauthn4j.validator.exception.MaliciousCounterValueException) {
            return new MaliciousCounterValueException("Malicious counter value is detected. Cloned authenticators exist in parallel.", e);
        } else if (e instanceof com.webauthn4j.validator.exception.MaliciousDataException) {
            return new MaliciousDataException("Bad client data type", e);
        } else if (e instanceof com.webauthn4j.validator.exception.MissingChallengeException) {
            return new MissingChallengeException("Missing challenge error", e);
        } else if (e instanceof com.webauthn4j.validator.exception.SelfAttestationProhibitedException) {
            return new SelfAttestationProhibitedException("Self attestation is specified while prohibited", e);
        } else if (e instanceof com.webauthn4j.validator.exception.TokenBindingException) {
            return new TokenBindingException("Token binding error", e);
        } else if (e instanceof com.webauthn4j.validator.exception.UnexpectedExtensionException) {
            return new UnexpectedExtensionException("Unexpected extension is contained", e);
        } else if (e instanceof com.webauthn4j.validator.exception.UserNotPresentException) {
            return new UserNotPresentException("User not verified", e);
        } else if (e instanceof com.webauthn4j.validator.exception.UserNotVerifiedException) {
            return new UserNotVerifiedException("User not verified", e);
        } else if (e instanceof com.webauthn4j.validator.exception.ValidationException) {
            return new AuthenticationServiceException("WebAuthn validation error", e);
        } else if (e instanceof com.webauthn4j.converter.exception.DataConversionException) {
            return new DataConversionException("Input data cannot be parsed", e);
        }
        return e;
    }
}
