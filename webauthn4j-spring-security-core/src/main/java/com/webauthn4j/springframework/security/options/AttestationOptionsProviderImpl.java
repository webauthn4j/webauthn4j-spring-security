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
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.exception.PrincipalNotFoundException;
import com.webauthn4j.springframework.security.extension.AuthenticationExtensionsClientInputsProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * An {@link AssertionOptionsProvider} implementation
 */
public class AttestationOptionsProviderImpl implements AttestationOptionsProvider {

    //~ Instance fields
    // ================================================================================================
    private String rpId = null;
    private String rpName = null;
    private List<PublicKeyCredentialParameters> pubKeyCredParams = new ArrayList<>();
    private AuthenticatorSelectionCriteria registrationAuthenticatorSelection;
    private AttestationConveyancePreference attestation;
    private Long registrationTimeout = null;
    private AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> registrationExtensions;

    private RpIdProvider rpIdProvider;
    private PublicKeyCredentialUserEntityProvider publicKeyCredentialUserEntityProvider = new DefaultPublicKeyCredentialUserEntityProvider();
    private final WebAuthnCredentialRecordService webAuthnCredentialRecordService;
    private final ChallengeRepository challengeRepository;
    private AuthenticationExtensionsClientInputsProvider<RegistrationExtensionClientInput> registrationExtensionsProvider = new DefaultRegistrationExtensionsProvider();

    // ~ Constructors
    // ===================================================================================================

    public AttestationOptionsProviderImpl(RpIdProvider rpIdProvider, WebAuthnCredentialRecordService webAuthnCredentialRecordService, ChallengeRepository challengeRepository) {

        Assert.notNull(webAuthnCredentialRecordService, "webAuthnCredentialRecordService must not be null");
        Assert.notNull(challengeRepository, "challengeRepository must not be null");

        this.rpIdProvider = rpIdProvider;
        this.webAuthnCredentialRecordService = webAuthnCredentialRecordService;
        this.challengeRepository = challengeRepository;
    }

    public AttestationOptionsProviderImpl(WebAuthnCredentialRecordService webAuthnCredentialRecordService, ChallengeRepository challengeRepository) {
        this(null, webAuthnCredentialRecordService, challengeRepository);
    }



    // ~ Methods
    // ========================================================================================================

    /**
     * {@inheritDoc}
     */
    public AttestationOptions getAttestationOptions(HttpServletRequest request, Authentication authentication) {

        PublicKeyCredentialRpEntity relyingParty = new PublicKeyCredentialRpEntity(getRpId(request), rpName);
        PublicKeyCredentialUserEntity user;
        try {
            user = getPublicKeyCredentialUserEntityProvider().provide(authentication);
        } catch (PrincipalNotFoundException e) {
            user = null;
        }

        return new AttestationOptions(
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


    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
        this.rpIdProvider = null;
    }

    public String getRpName() {
        return rpName;
    }

    public void setRpName(String rpName) {
        Assert.hasText(rpName, "rpName parameter must not be empty or null");
        this.rpName = rpName;
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

    public Long getRegistrationTimeout() {
        return registrationTimeout;
    }

    public void setRegistrationTimeout(Long registrationTimeout) {
        Assert.notNull(registrationTimeout, "registrationTimeout must not be null.");
        Assert.isTrue(registrationTimeout >= 0, "registrationTimeout must be within unsigned long.");
        this.registrationTimeout = registrationTimeout;
    }

    public AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> getRegistrationExtensions() {
        return registrationExtensions;
    }

    public void setRegistrationExtensions(AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> registrationExtensions) {
        this.registrationExtensions = registrationExtensions;
    }

    public RpIdProvider getRpIdProvider() {
        return rpIdProvider;
    }

    public void setRpIdProvider(RpIdProvider rpIdProvider) {
        this.rpId = null;
        this.rpIdProvider = rpIdProvider;
    }

    public AuthenticationExtensionsClientInputsProvider<RegistrationExtensionClientInput> getRegistrationExtensionsProvider() {
        return registrationExtensionsProvider;
    }

    public void setRegistrationExtensionsProvider(AuthenticationExtensionsClientInputsProvider<RegistrationExtensionClientInput> registrationExtensionsProvider) {
        Assert.notNull(registrationExtensionsProvider, "registrationExtensionsProvider must not be null");
        this.registrationExtensionsProvider = registrationExtensionsProvider;
    }

    public WebAuthnCredentialRecordService getWebAuthnCredentialRecordService() {
        return webAuthnCredentialRecordService;
    }

    public void setPublicKeyCredentialUserEntityProvider(PublicKeyCredentialUserEntityProvider publicKeyCredentialUserEntityProvider) {
        Assert.notNull(publicKeyCredentialUserEntityProvider, "webAuthnUserHandleProvider must not be null");
        this.publicKeyCredentialUserEntityProvider = publicKeyCredentialUserEntityProvider;
    }

    public PublicKeyCredentialUserEntityProvider getPublicKeyCredentialUserEntityProvider() {
        return publicKeyCredentialUserEntityProvider;
    }

    protected ChallengeRepository getChallengeRepository() {
        return challengeRepository;
    }

    protected List<PublicKeyCredentialDescriptor> getCredentials(Authentication authentication){
        if(authentication == null){
            return Collections.emptyList();
        }
        try {
            return getWebAuthnCredentialRecordService().loadCredentialRecordsByUserPrincipal(authentication.getName()).stream()
                    .map(credentialRecord -> new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credentialRecord.getAttestedCredentialData().getCredentialId(), credentialRecord.getTransports()))
                    .collect(Collectors.toList());
        } catch (PrincipalNotFoundException e) {
            return Collections.emptyList();
        }
    }

    String getRpId(HttpServletRequest request) {
        if(rpIdProvider != null){
            return rpIdProvider.provide(request);
        }
        else {
            return rpId;
        }
    }

    static class DefaultPublicKeyCredentialUserEntityProvider implements PublicKeyCredentialUserEntityProvider {

        @Override
        public PublicKeyCredentialUserEntity provide(Authentication authentication) {
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

}
