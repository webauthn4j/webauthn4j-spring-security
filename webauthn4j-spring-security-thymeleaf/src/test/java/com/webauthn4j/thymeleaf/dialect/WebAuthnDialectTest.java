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

package com.webauthn4j.thymeleaf.dialect;

import com.webauthn4j.thymeleaf.dialect.processor.ChallengeAttrProcessor;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnDialectTest {

    @Test
    public void initialize_with_prefix() {
        WebAuthnDialect target = new WebAuthnDialect("prefix");
        assertThat(target.getPrefix()).isEqualTo("prefix");
        assertThat(target.getProcessors("prefix")).hasSize(1);
        assertThat(target.getProcessors("prefix")).first().isInstanceOf(ChallengeAttrProcessor.class);
    }

    @Test
    public void initialize_without_prefix() {
        WebAuthnDialect target = new WebAuthnDialect();
        assertThat(target.getPrefix()).isEqualTo("webauthn");
        assertThat(target.getProcessors("prefix")).hasSize(1);
        assertThat(target.getProcessors("prefix")).first().isInstanceOf(ChallengeAttrProcessor.class);
    }

}
