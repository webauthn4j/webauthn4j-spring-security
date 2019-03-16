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

package net.sharplab.thymeleaf.dialect.processor;

import com.webauthn4j.data.client.challenge.Challenge;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import org.springframework.context.ApplicationContext;
import org.thymeleaf.context.ITemplateContext;
import org.thymeleaf.context.IWebContext;
import org.thymeleaf.engine.AttributeName;
import org.thymeleaf.model.IProcessableElementTag;
import org.thymeleaf.processor.element.AbstractAttributeTagProcessor;
import org.thymeleaf.processor.element.IElementTagStructureHandler;
import org.thymeleaf.spring5.context.SpringContextUtils;
import org.thymeleaf.templatemode.TemplateMode;

import javax.servlet.http.HttpServletRequest;

public class ChallengeAttrProcessor extends AbstractAttributeTagProcessor {

    public static final String TARGET_ATTR_NAME = "content";

    public ChallengeAttrProcessor(String prefix, int precedence) {
        super(TemplateMode.HTML,
                prefix,
                "meta",
                false,
                "challenge",
                true,
                precedence,
                true);
    }

    @Override
    protected void doProcess(ITemplateContext context, IProcessableElementTag tag, AttributeName attributeName, String attributeValue, IElementTagStructureHandler structureHandler) {
        Challenge challenge = getChallenge(context);
        String challengeValue = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue());
        structureHandler.setAttribute(TARGET_ATTR_NAME, challengeValue);
    }

    private Challenge getChallenge(ITemplateContext context) {
        ApplicationContext applicationContext = SpringContextUtils.getApplicationContext(context);
        IWebContext webContext = (IWebContext) context;
        HttpServletRequest httpServletRequest = webContext.getRequest();
        ChallengeRepository challengeRepository = applicationContext.getBean(ChallengeRepository.class);
        Challenge challenge = challengeRepository.loadChallenge(httpServletRequest);
        if (challenge == null) {
            challenge = challengeRepository.generateChallenge();
            challengeRepository.saveChallenge(challenge, httpServletRequest);
        }
        return challenge;
    }
}
