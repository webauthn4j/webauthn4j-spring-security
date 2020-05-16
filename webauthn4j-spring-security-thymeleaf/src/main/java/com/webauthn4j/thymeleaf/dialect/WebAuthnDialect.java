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
import org.thymeleaf.dialect.AbstractDialect;
import org.thymeleaf.dialect.IProcessorDialect;
import org.thymeleaf.processor.IProcessor;

import java.util.LinkedHashSet;
import java.util.Set;

public class WebAuthnDialect extends AbstractDialect implements IProcessorDialect {

    public static final String NAME = "webauthn";
    public static final String DEFAULT_PREFIX = "webauthn";
    public static final int PROCESSOR_PRECEDENCE = 800;

    private String prefix = DEFAULT_PREFIX;

    public WebAuthnDialect() {
        super(NAME);
    }

    public WebAuthnDialect(String prefix) {
        super(NAME);
        this.prefix = prefix;
    }

    @Override
    public String getPrefix() {
        return prefix;
    }

    @Override
    public int getDialectProcessorPrecedence() {
        return PROCESSOR_PRECEDENCE;
    }

    @Override
    public Set<IProcessor> getProcessors(String dialectPrefix) {
        final Set<IProcessor> processors = new LinkedHashSet<>();
        processors.add(new ChallengeAttrProcessor(getPrefix(), getDialectProcessorPrecedence()));
        return processors;
    }

}
