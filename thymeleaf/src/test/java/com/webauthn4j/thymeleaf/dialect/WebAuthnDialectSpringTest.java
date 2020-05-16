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

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.springframework.security.webauthn.challenge.ChallengeRepository;
import org.junit.Test;
import org.thymeleaf.testing.templateengine.context.web.SpringWebProcessingContextBuilder;
import org.thymeleaf.testing.templateengine.engine.TestExecutor;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnDialectSpringTest {

    @Test
    public void test() {
        SpringWebProcessingContextBuilder springWebProcessingContextBuilder = new SpringWebProcessingContextBuilder();
        springWebProcessingContextBuilder.setApplicationContextConfigLocation("classpath:com/webauthn4j/thymeleaf/dialect/processor/WebAuthnDialectSpringTest/applicationContext.xml");

        final TestExecutor executor = new TestExecutor();
        executor.setProcessingContextBuilder(springWebProcessingContextBuilder);
        executor.setDialects(Collections.singletonList(new WebAuthnDialect()));

        executor.execute("classpath:com/webauthn4j/thymeleaf/dialect/processor/WebAuthnDialectSpringTest/test.thtest");
        assertThat(executor.getReporter().isAllOK()).isTrue();
    }

    @Test
    public void loadChallenge_null_test() {
        SpringWebProcessingContextBuilder springWebProcessingContextBuilder = new SpringWebProcessingContextBuilder();
        springWebProcessingContextBuilder.setApplicationContextConfigLocation("classpath:com/webauthn4j/thymeleaf/dialect/processor/WebAuthnDialectSpringTest/loadChallenge_null_applicationContext.xml");

        final TestExecutor executor = new TestExecutor();
        executor.setProcessingContextBuilder(springWebProcessingContextBuilder);
        executor.setDialects(Collections.singletonList(new WebAuthnDialect()));

        executor.execute("classpath:com/webauthn4j/thymeleaf/dialect/processor/WebAuthnDialectSpringTest/test.thtest");
        assertThat(executor.getReporter().isAllOK()).isTrue();
    }

    public static class ChallengeRepositoryMock implements ChallengeRepository{

        @Override
        public Challenge generateChallenge() {
            return new DefaultChallenge("rs04mVhERNi-DZrEQT1hwA");
        }

        @Override
        public void saveChallenge(Challenge challenge, HttpServletRequest request) {
            //nop
        }

        @Override
        public Challenge loadChallenge(HttpServletRequest request) {
            return new DefaultChallenge("rs04mVhERNi-DZrEQT1hwA");
        }
    }

    public static class LoadChallengeNullChallengeRepositoryMock implements ChallengeRepository{

        @Override
        public Challenge generateChallenge() {
            return new DefaultChallenge("rs04mVhERNi-DZrEQT1hwA");
        }

        @Override
        public void saveChallenge(Challenge challenge, HttpServletRequest request) {
            //nop
        }

        @Override
        public Challenge loadChallenge(HttpServletRequest request) {
            return null;
        }
    }
}
