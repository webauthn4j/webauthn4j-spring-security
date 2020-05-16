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

package com.webauthn4j.springframework.security.webauthn.sample.domain.exception;

import org.terasoluna.gfw.common.message.ResultMessages;

/**
 * Business Exception for WebAuthn Sample
 */
@SuppressWarnings("squid:MaximumInheritanceDepth")
public class WebAuthnSampleBusinessException extends org.terasoluna.gfw.common.exception.BusinessException {

    /**
     * Constructor for specify a message.
     * <p>
     * generate a {@link ResultMessages} instance of error type and addExtension a message.
     * </p>
     *
     * @param message result message
     */
    public WebAuthnSampleBusinessException(String message) {
        super(message);
    }

    /**
     * Constructor for specify messages.
     * <p>
     * Takes multiple {@code String} messages as argument.
     * </p>
     *
     * @param messages {@link ResultMessages} instance
     */
    public WebAuthnSampleBusinessException(ResultMessages messages) {
        super(messages);
    }

    /**
     * Constructor for specify messages and exception.
     * <p>
     * Takes multiple {@code String} messages and cause of exception as argument.
     * </p>
     *
     * @param messages {@link ResultMessages} instance
     * @param cause    {@link Throwable} instance
     */
    public WebAuthnSampleBusinessException(ResultMessages messages, Throwable cause) {
        super(messages, cause);
    }
}
