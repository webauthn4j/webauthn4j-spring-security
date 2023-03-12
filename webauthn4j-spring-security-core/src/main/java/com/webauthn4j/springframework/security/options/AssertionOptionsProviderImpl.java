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

package com.webauthn4j.springframework.security.options;

import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.exception.PrincipalNotFoundException;
import com.webauthn4j.springframework.security.extension.AuthenticationExtensionsClientInputsProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * An {@link AssertionOptionsProvider} implementation
 */
public class AssertionOptionsProviderImpl implements AssertionOptionsProvider {

    //~ Instance fields
    // ================================================================================================
    private String rpId = null;
    private UserVerificationRequirement authenticationUserVerification;
    private Long authenticationTimeout = null;
    private AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> authenticationExtensions;

    private RpIdProvider rpIdProvider;
    private final WebAuthnAuthenticatorService authenticatorService;
    private final ChallengeRepository challengeRepository;
    private AuthenticationExtensionsClientInputsProvider<AuthenticationExtensionClientInput> authenticationExtensionsProvider = new DefaultAuthenticationExtensionsProvider();

    // ~ Constructors
    // ===================================================================================================

    public AssertionOptionsProviderImpl(RpIdProvider rpIdProvider, WebAuthnAuthenticatorService authenticatorService, ChallengeRepository challengeRepository) {

        Assert.notNull(authenticatorService, "authenticatorService must not be null");
        Assert.notNull(challengeRepository, "challengeRepository must not be null");

        this.rpIdProvider = rpIdProvider;
        this.authenticatorService = authenticatorService;
        this.challengeRepository = challengeRepository;
    }

    public AssertionOptionsProviderImpl(WebAuthnAuthenticatorService authenticatorService, ChallengeRepository challengeRepository) {
        this(null, authenticatorService, challengeRepository);
    }


    // ~ Methods
    // ========================================================================================================
    /**
     * {@inheritDoc}
     */
    public AssertionOptions getAssertionOptions(HttpServletRequest request, Authentication authentication) {
        return new AssertionOptions(
                getChallengeRepository().loadOrGenerateChallenge(request),
                getAuthenticationTimeout(),
                getRpId(request),
                getCredentials(authentication),
                getAuthenticationUserVerification(),
                getAuthenticationExtensionsProvider().provide(request));
    }


    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
        this.rpIdProvider = null;
    }

    public UserVerificationRequirement getAuthenticationUserVerification() {
        return authenticationUserVerification;
    }

    public void setAuthenticationUserVerification(UserVerificationRequirement authenticationUserVerification) {
        this.authenticationUserVerification = authenticationUserVerification;
    }

    public Long getAuthenticationTimeout() {
        return authenticationTimeout;
    }

    public void setAuthenticationTimeout(Long authenticationTimeout) {
        Assert.notNull(authenticationTimeout, "authenticationTimeout must not be null.");
        Assert.isTrue(authenticationTimeout >= 0, "registrationTimeout must be within unsigned long.");
        this.authenticationTimeout = authenticationTimeout;
    }

    public AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> getAuthenticationExtensions() {
        return authenticationExtensions;
    }

    public void setAuthenticationExtensions(AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> authenticationExtensions) {
        this.authenticationExtensions = authenticationExtensions;
    }

    public RpIdProvider getRpIdProvider() {
        return rpIdProvider;
    }

    public void setRpIdProvider(RpIdProvider rpIdProvider) {
        this.rpId = null;
        this.rpIdProvider = rpIdProvider;
    }

    public AuthenticationExtensionsClientInputsProvider<AuthenticationExtensionClientInput> getAuthenticationExtensionsProvider() {
        return authenticationExtensionsProvider;
    }

    public void setAuthenticationExtensionsProvider(AuthenticationExtensionsClientInputsProvider<AuthenticationExtensionClientInput> authenticationExtensionsProvider) {
        Assert.notNull(authenticationExtensionsProvider, "registrationExtensionsProvider must not be null");
        this.authenticationExtensionsProvider = authenticationExtensionsProvider;
    }

    public WebAuthnAuthenticatorService getAuthenticatorService() {
        return authenticatorService;
    }

    protected ChallengeRepository getChallengeRepository() {
        return challengeRepository;
    }


    String getRpId(HttpServletRequest request) {
        if(rpIdProvider != null){
            return rpIdProvider.provide(request);
        }
        return rpId;
    }

    protected List<PublicKeyCredentialDescriptor> getCredentials(Authentication authentication){
        if(authentication == null){
            return Collections.emptyList();
        }
        try {
            return getAuthenticatorService().loadAuthenticatorsByUserPrincipal(authentication.getName()).stream()
                    .map(authenticator -> new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, authenticator.getAttestedCredentialData().getCredentialId(), authenticator.getTransports()))
                    .collect(Collectors.toList());
        } catch (PrincipalNotFoundException e) {
            return Collections.emptyList();
        }
    }

    class DefaultAuthenticationExtensionsProvider implements AuthenticationExtensionsClientInputsProvider<AuthenticationExtensionClientInput> {
        @Override
        public AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> provide(HttpServletRequest httpServletRequest) {
            return authenticationExtensions;
        }
    }

}
