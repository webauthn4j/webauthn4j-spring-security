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

package com.webauthn4j.springframework.security.config.configurers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.converter.jackson.WebAuthn4JSpringSecurityJSONModule;
import com.webauthn4j.springframework.security.endpoint.AssertionOptionsEndpointFilter;
import com.webauthn4j.springframework.security.endpoint.AttestationOptionsEndpointFilter;
import com.webauthn4j.springframework.security.options.*;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

/**
 * Internal utility for WebAuthn Configurers
 */
class WebAuthnConfigurerUtil {

    private WebAuthnConfigurerUtil() {
    }

    /**
     * Get {@link ChallengeRepository} from SharedObject or ApplicationContext. if nothing hit, create new instance
     */
    static <H extends HttpSecurityBuilder<H>> ChallengeRepository getChallengeRepositoryOrCreateNew(H http) {
        ChallengeRepository challengeRepository = http.getSharedObject(ChallengeRepository.class);
        if (challengeRepository != null) {
            return challengeRepository;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(ChallengeRepository.class);
        if (beanNames.length == 0) {
            return new HttpSessionChallengeRepository();
        } else {
            return applicationContext.getBean(ChallengeRepository.class);
        }
    }

    /**
     * Get {@link RpIdProvider} from SharedObject or ApplicationContext. if nothing hit, throw exception
     */
    static <H extends HttpSecurityBuilder<H>> WebAuthnAuthenticatorService getWebAuthnAuthenticatorServiceOrThrowException(H http){
        WebAuthnAuthenticatorService webAuthnAuthenticatorService = http.getSharedObject(WebAuthnAuthenticatorService.class);
        if (webAuthnAuthenticatorService != null) {
            return webAuthnAuthenticatorService;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        // WebAuthnAuthenticatorService must be provided manually. If not, let it throw exception.
        return applicationContext.getBean(WebAuthnAuthenticatorService.class);
    }

    /**
     * Get {@link RpIdProvider} from SharedObject or ApplicationContext. if nothing hit, return null
     */
    static <H extends HttpSecurityBuilder<H>> RpIdProvider getRpIdProviderOrNull(H http) {
        RpIdProvider rpIdProvider = http.getSharedObject(RpIdProvider.class);
        if (rpIdProvider != null) {
            return rpIdProvider;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(RpIdProvider.class);
        if(beanNames.length == 0){
            rpIdProvider = null;
        }
        else {
            rpIdProvider = applicationContext.getBean(RpIdProvider.class);
        }
        http.setSharedObject(RpIdProvider.class, rpIdProvider);
        return rpIdProvider;
    }

    /**
     * Get {@link AttestationOptionsProvider} from SharedObject or ApplicationContext. if nothing hit, create new
     */
    static <H extends HttpSecurityBuilder<H>> AttestationOptionsProvider getAttestationOptionsProviderOrCreateNew(H http) {
        AttestationOptionsProvider optionsProvider = http.getSharedObject(AttestationOptionsProvider.class);
        if (optionsProvider != null) {
            return optionsProvider;
        }
        AttestationOptionsProvider attestationOptionsProvider;
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(AttestationOptionsProvider.class);
        if(beanNames.length == 0){
            attestationOptionsProvider = new AttestationOptionsProviderImpl(getRpIdProviderOrNull(http), getWebAuthnAuthenticatorServiceOrThrowException(http), getChallengeRepositoryOrCreateNew(http));
        }
        else {
            attestationOptionsProvider = applicationContext.getBean(AttestationOptionsProvider.class);
        }
        http.setSharedObject(AttestationOptionsProvider.class, attestationOptionsProvider);
        return attestationOptionsProvider;
    }

    /**
     * Get {@link AssertionOptionsProvider} from SharedObject or ApplicationContext. if nothing hit, create new
     */
    static <H extends HttpSecurityBuilder<H>> AssertionOptionsProvider getAssertionOptionsProviderOrCreateNew(H http) {
        AssertionOptionsProvider optionsProvider = http.getSharedObject(AssertionOptionsProvider.class);
        if (optionsProvider != null) {
            return optionsProvider;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(AssertionOptionsProvider.class);
        if(beanNames.length == 0){
            return new AssertionOptionsProviderImpl(getRpIdProviderOrNull(http), getWebAuthnAuthenticatorServiceOrThrowException(http), getChallengeRepositoryOrCreateNew(http));
        }
        else {
            return applicationContext.getBean(AssertionOptionsProvider.class);
        }
    }

    /**
     * Get {@link ObjectConverter} from SharedObject or ApplicationContext. if nothing hit, create new
     */
    public static <H extends HttpSecurityBuilder<H>> ObjectConverter getObjectConverterOrCreateNew(H http) {
        ObjectConverter objectConverter = http.getSharedObject(ObjectConverter.class);
        if (objectConverter != null) {
            return objectConverter;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(ObjectConverter.class);
        if (beanNames.length == 0) {
            ObjectMapper jsonMapper = new ObjectMapper();
            jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
            jsonMapper.registerModule(new WebAuthn4JSpringSecurityJSONModule());
            ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            return new ObjectConverter(jsonMapper, cborMapper);
        } else {
            return applicationContext.getBean(ObjectConverter.class);
        }
    }

    /**
     * Get {@link ServerPropertyProvider} from SharedObject or ApplicationContext. if nothing hit, create new
     */
    static <H extends HttpSecurityBuilder<H>> ServerPropertyProvider getServerPropertyProviderOrCreateNew(H http) {
        ServerPropertyProvider serverPropertyProvider = http.getSharedObject(ServerPropertyProvider.class);
        if (serverPropertyProvider != null) {
            return serverPropertyProvider;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(ServerPropertyProvider.class);
        if (beanNames.length == 0) {
            return new ServerPropertyProviderImpl(getChallengeRepositoryOrCreateNew(http));
        } else {
            return applicationContext.getBean(ServerPropertyProvider.class);
        }
    }

    /**
     * Get {@link AssertionOptionsProvider} from SharedObject or ApplicationContext. if nothing hit, create new
     */
    public static <H extends HttpSecurityBuilder<H>> AttestationOptionsEndpointFilter getAttestationOptionsEndpointFilterOrCreateNew(H http) {
        AttestationOptionsEndpointFilter attestationOptionsEndpointFilter = http.getSharedObject(AttestationOptionsEndpointFilter.class);
        if (attestationOptionsEndpointFilter != null) {
            return attestationOptionsEndpointFilter;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(AttestationOptionsEndpointFilter.class);
        if (beanNames.length == 0) {
            return new AttestationOptionsEndpointFilter(getAttestationOptionsProviderOrCreateNew(http), getObjectConverterOrCreateNew(http));
        } else {
            return applicationContext.getBean(AttestationOptionsEndpointFilter.class);
        }
    }

    /**
     * Get {@link AssertionOptionsProvider} from SharedObject or ApplicationContext. if nothing hit, create new
     */
    public static <H extends HttpSecurityBuilder<H>> AssertionOptionsEndpointFilter getAssertionOptionsEndpointFilterOrCreateNew(H http) {
        AssertionOptionsEndpointFilter assertionOptionsEndpointFilter = http.getSharedObject(AssertionOptionsEndpointFilter.class);
        if (assertionOptionsEndpointFilter != null) {
            return assertionOptionsEndpointFilter;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        String[] beanNames = applicationContext.getBeanNamesForType(AssertionOptionsEndpointFilter.class);
        if (beanNames.length == 0) {
            return new AssertionOptionsEndpointFilter(getAssertionOptionsProviderOrCreateNew(http), getObjectConverterOrCreateNew(http));
        } else {
            return applicationContext.getBean(AssertionOptionsEndpointFilter.class);
        }
    }


}
