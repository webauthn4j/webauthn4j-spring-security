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

package com.webauthn4j.springframework.security.webauthn;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.context.support.ResourceBundleMessageSource;

/**
 * The default <code>MessageSource</code> used by WebAuthn4J Spring Security.
 * <p>
 * All WebAuthn4J Spring Security classes requiring message localization will by default use this
 * class. However, all such classes will also implement <code>MessageSourceAware</code> so
 * that the application context can inject an alternative message source. Therefore this
 * class is only used when the deployment environment has not specified an alternative
 * message source.
 * </p>
 * <p>
 * This class design is based on {@link org.springframework.security.core.SpringSecurityMessageSource}
 */
public class SpringSecurityWebAuthnMessageSource extends ResourceBundleMessageSource {
    // ~ Constructors
    // ===================================================================================================

    public SpringSecurityWebAuthnMessageSource() {
        setBasename("com.webauthn4j.springframework.security.webauthn.messages");
    }

    // ~ Methods
    // ========================================================================================================

    public static MessageSourceAccessor getAccessor() {
        return new MessageSourceAccessor(new SpringSecurityWebAuthnMessageSource());
    }
}