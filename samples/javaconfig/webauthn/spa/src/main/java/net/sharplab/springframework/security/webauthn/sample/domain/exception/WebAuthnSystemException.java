/*
 *    Copyright 2002-2019 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.sample.domain.exception;

import org.terasoluna.gfw.common.exception.ExceptionCodeProvider;

/**
 * System Exception for WebAuthn Sample
 */
@SuppressWarnings("squid:MaximumInheritanceDepth")
public class WebAuthnSystemException extends org.terasoluna.gfw.common.exception.SystemException {


    /**
     * Constructor<br>
     * <p>
     * {@link ExceptionCodeProvider}, message to be displayed and underlying cause of exception can be specified.
     * </p>
     *
     * @param code    ExceptionCode {@link ExceptionCodeProvider}
     * @param message message to be displayed
     * @param cause   underlying cause of exception
     */
    public WebAuthnSystemException(String code, String message, Throwable cause) {
        super(code, message, cause);
    }

    /**
     * Constructor<br>
     * <p>
     * {@link ExceptionCodeProvider}, message to be displayed can be specified.
     * </p>
     *
     * @param code    ExceptionCode {@link ExceptionCodeProvider}
     * @param message message to be displayed
     */
    public WebAuthnSystemException(String code, String message) {
        super(code, message);
    }

    /**
     * Constructor<br>
     * <p>
     * {@link ExceptionCodeProvider} and underlying cause of exception can be specified.
     * </p>
     *
     * @param code  ExceptionCode {@link ExceptionCodeProvider}
     * @param cause underlying cause of exception
     */
    public WebAuthnSystemException(String code, Throwable cause) {
        super(code, cause);
    }
}
