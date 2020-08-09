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

import com.webauthn4j.data.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.exception.PrincipalNotFoundException;
import com.webauthn4j.springframework.security.util.internal.ServletUtil;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * An {@link OptionsProvider} implementation
 */
public class OptionsProviderImpl implements OptionsProvider {

    //~ Instance fields
    // ================================================================================================
    private String rpId = null;
    private String rpName = null;
    private String rpIcon = null;
    private List<PublicKeyCredentialParameters> pubKeyCredParams = new ArrayList<>();
    private AuthenticatorSelectionCriteria registrationAuthenticatorSelection;
    private AttestationConveyancePreference attestation;
    private UserVerificationRequirement authenticationUserVerification;
    private Long registrationTimeout = null;
    private Long authenticationTimeout = null;
    private AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> registrationExtensions;
    private AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> authenticationExtensions;

    private final WebAuthnAuthenticatorService authenticatorService;
    private final ChallengeRepository challengeRepository;
    private PublicKeyCredentialUserEntityService publicKeyCredentialUserEntityService = new DefaultPublicKeyCredentialUserEntityService();
    private AuthenticationExtensionsClientInputsProvider<RegistrationExtensionClientInput> registrationExtensionsProvider = new DefaultRegistrationExtensionsProvider();
    private AuthenticationExtensionsClientInputsProvider<AuthenticationExtensionClientInput> authenticationExtensionsProvider = new DefaultAuthenticationExtensionsProvider();

    // ~ Constructors
    // ===================================================================================================

    public OptionsProviderImpl(WebAuthnAuthenticatorService authenticatorService, ChallengeRepository challengeRepository) {

        Assert.notNull(authenticatorService, "authenticatorService must not be null");
        Assert.notNull(challengeRepository, "challengeRepository must not be null");

        this.authenticatorService = authenticatorService;
        this.challengeRepository = challengeRepository;
    }


    // ~ Methods
    // ========================================================================================================

    /**
     * {@inheritDoc}
     */
    public PublicKeyCredentialCreationOptions getAttestationOptions(HttpServletRequest request, Authentication authentication) {

        PublicKeyCredentialRpEntity relyingParty = new PublicKeyCredentialRpEntity(getEffectiveRpId(request), rpName, rpIcon);
        PublicKeyCredentialUserEntity user;
        try {
            user = publicKeyCredentialUserEntityService.loadUserByAuthentication(authentication);
        } catch (PrincipalNotFoundException e) {
            user = null;
        }

        return new PublicKeyCredentialCreationOptions(
                relyingParty,
                user,
                getChallengeRepository().loadOrGenerateChallenge(request),
                getPubKeyCredParams(),
                getRegistrationTimeout(),
                getCredentials(authentication),
                getRegistrationAuthenticatorSelection(),
                getAttestation(),
                getRegistrationExtensionsProvider().provide(request));
    }

    /**
     * {@inheritDoc}
     */
    public PublicKeyCredentialRequestOptions getAssertionOptions(HttpServletRequest request, Authentication authentication) {
        return new PublicKeyCredentialRequestOptions(
                getChallengeRepository().loadOrGenerateChallenge(request),
                getAuthenticationTimeout(),
                getEffectiveRpId(request),
                getCredentials(authentication),
                getAuthenticationUserVerification(),
                getAuthenticationExtensionsProvider().provide(request));
    }

    /**
     * {@inheritDoc}
     */
    public String getEffectiveRpId(HttpServletRequest request) {
        String effectiveRpId;
        if (this.rpId != null) {
            effectiveRpId = this.rpId;
        } else {
            Origin origin = ServletUtil.getOrigin(request);
            effectiveRpId = origin.getHost();
        }
        return effectiveRpId;
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public String getRpName() {
        return rpName;
    }

    public void setRpName(String rpName) {
        Assert.hasText(rpName, "rpName parameter must not be empty or null");
        this.rpName = rpName;
    }

    public String getRpIcon() {
        return rpIcon;
    }

    public void setRpIcon(String rpIcon) {
        Assert.hasText(rpIcon, "rpIcon parameter must not be empty or null");
        this.rpIcon = rpIcon;
    }

    public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public void setPubKeyCredParams(List<PublicKeyCredentialParameters> pubKeyCredParams) {
        this.pubKeyCredParams = pubKeyCredParams;
    }

    public AuthenticatorSelectionCriteria getRegistrationAuthenticatorSelection() {
        return registrationAuthenticatorSelection;
    }

    public void setRegistrationAuthenticatorSelection(AuthenticatorSelectionCriteria registrationAuthenticatorSelection) {
        this.registrationAuthenticatorSelection = registrationAuthenticatorSelection;
    }

    public AttestationConveyancePreference getAttestation() {
        return attestation;
    }

    public void setAttestation(AttestationConveyancePreference attestation) {
        this.attestation = attestation;
    }

    public UserVerificationRequirement getAuthenticationUserVerification() {
        return authenticationUserVerification;
    }

    public void setAuthenticationUserVerification(UserVerificationRequirement authenticationUserVerification) {
        this.authenticationUserVerification = authenticationUserVerification;
    }

    public Long getRegistrationTimeout() {
        return registrationTimeout;
    }

    public void setRegistrationTimeout(Long registrationTimeout) {
        Assert.notNull(registrationTimeout, "registrationTimeout must not be null.");
        Assert.isTrue(registrationTimeout >= 0, "registrationTimeout must be within unsigned long.");
        this.registrationTimeout = registrationTimeout;
    }

    public Long getAuthenticationTimeout() {
        return authenticationTimeout;
    }

    public void setAuthenticationTimeout(Long authenticationTimeout) {
        Assert.notNull(authenticationTimeout, "authenticationTimeout must not be null.");
        Assert.isTrue(authenticationTimeout >= 0, "registrationTimeout must be within unsigned long.");
        this.authenticationTimeout = authenticationTimeout;
    }

    public AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> getRegistrationExtensions() {
        return registrationExtensions;
    }

    public void setRegistrationExtensions(AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> registrationExtensions) {
        this.registrationExtensions = registrationExtensions;
    }

    public AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> getAuthenticationExtensions() {
        return authenticationExtensions;
    }

    public void setAuthenticationExtensions(AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> authenticationExtensions) {
        this.authenticationExtensions = authenticationExtensions;
    }

    public AuthenticationExtensionsClientInputsProvider<RegistrationExtensionClientInput> getRegistrationExtensionsProvider() {
        return registrationExtensionsProvider;
    }

    public void setRegistrationExtensionsProvider(AuthenticationExtensionsClientInputsProvider<RegistrationExtensionClientInput> registrationExtensionsProvider) {
        Assert.notNull(registrationExtensionsProvider, "registrationExtensionsProvider must not be null");
        this.registrationExtensionsProvider = registrationExtensionsProvider;
    }

    public AuthenticationExtensionsClientInputsProvider<AuthenticationExtensionClientInput> getAuthenticationExtensionsProvider() {
        return authenticationExtensionsProvider;
    }

    public void setAuthenticationExtensionsProvider(AuthenticationExtensionsClientInputsProvider<AuthenticationExtensionClientInput> authenticationExtensionsProvider) {
        Assert.notNull(registrationExtensionsProvider, "registrationExtensionsProvider must not be null");
        this.authenticationExtensionsProvider = authenticationExtensionsProvider;
    }

    public WebAuthnAuthenticatorService getAuthenticatorService() {
        return authenticatorService;
    }

    public void setPublicKeyCredentialUserEntityService(PublicKeyCredentialUserEntityService publicKeyCredentialUserEntityService) {
        Assert.notNull(publicKeyCredentialUserEntityService, "webAuthnUserHandleProvider must not be null");
        this.publicKeyCredentialUserEntityService = publicKeyCredentialUserEntityService;
    }

    public PublicKeyCredentialUserEntityService getPublicKeyCredentialUserEntityService() {
        return publicKeyCredentialUserEntityService;
    }

    protected ChallengeRepository getChallengeRepository() {
        return challengeRepository;
    }

    protected List<PublicKeyCredentialDescriptor> getCredentials(Authentication authentication){
        if(authentication == null){
            return Collections.emptyList();
        }
        Collection<? extends WebAuthnAuthenticator> authenticators;
        try {
            authenticators = authenticatorService.loadAuthenticatorsByUserPrincipal(authentication.getName());
        } catch (PrincipalNotFoundException e) {
            authenticators = Collections.emptyList();
        }
        List<PublicKeyCredentialDescriptor> credentials = new ArrayList<>();
        for (WebAuthnAuthenticator authenticator : authenticators) {
            credentials.add(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, authenticator.getAttestedCredentialData().getCredentialId(), authenticator.getTransports()));
        }
        return credentials;
    }


    static class DefaultPublicKeyCredentialUserEntityService implements PublicKeyCredentialUserEntityService {

        @Override
        public PublicKeyCredentialUserEntity loadUserByAuthentication(Authentication authentication) {
            if(authentication == null){
                return null;
            }
            String username = authentication.getName();
            return new PublicKeyCredentialUserEntity(
                    username.getBytes(StandardCharsets.UTF_8),
                    username,
                    username
            );
        }
    }

    class DefaultRegistrationExtensionsProvider implements AuthenticationExtensionsClientInputsProvider<RegistrationExtensionClientInput> {
        @Override
        public AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> provide(HttpServletRequest httpServletRequest) {
            return registrationExtensions;
        }
    }

    class DefaultAuthenticationExtensionsProvider implements AuthenticationExtensionsClientInputsProvider<AuthenticationExtensionClientInput> {
        @Override
        public AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> provide(HttpServletRequest httpServletRequest) {
            return authenticationExtensions;
        }
    }

}
