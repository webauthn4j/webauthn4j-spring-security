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
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.util.internal.ServletUtil;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
    private Long registrationTimeout = null;
    private Long authenticationTimeout = null;
    private AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> registrationExtensions = new AuthenticationExtensionsClientInputs<>();
    private AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> authenticationExtensions = new AuthenticationExtensionsClientInputs<>();

    private final WebAuthnAuthenticatorService authenticatorService;
    private final PublicKeyCredentialUserEntityService publicKeyCredentialUserEntityService;
    private final ChallengeRepository challengeRepository;

    // ~ Constructors
    // ===================================================================================================

    public OptionsProviderImpl(WebAuthnAuthenticatorService authenticatorService, PublicKeyCredentialUserEntityService publicKeyCredentialUserEntityService, ChallengeRepository challengeRepository) {

        Assert.notNull(authenticatorService, "authenticatorService must not be null");
        Assert.notNull(publicKeyCredentialUserEntityService, "webAuthnUserHandleProvider must not be null");
        Assert.notNull(challengeRepository, "challengeRepository must not be null");

        this.authenticatorService = authenticatorService;
        this.publicKeyCredentialUserEntityService = publicKeyCredentialUserEntityService;
        this.challengeRepository = challengeRepository;
    }

    public OptionsProviderImpl(WebAuthnAuthenticatorService authenticatorService, ChallengeRepository challengeRepository) {
        this(authenticatorService, new DefaultPublicKeyCredentialUserEntityService(), challengeRepository);
    }


    // ~ Methods
    // ========================================================================================================

    /**
     * {@inheritDoc}
     */
    public AttestationOptions getAttestationOptions(HttpServletRequest request, String username, Challenge challenge) {

        PublicKeyCredentialUserEntity user;
        Collection<? extends WebAuthnAuthenticator> authenticators;

        try {
            authenticators = authenticatorService.loadAuthenticatorsByPrincipal(username);
            user = publicKeyCredentialUserEntityService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            authenticators = Collections.emptyList();
            user = null;
        }

        List<PublicKeyCredentialDescriptor> credentials = new ArrayList<>();
        for (WebAuthnAuthenticator authenticator : authenticators) {
            byte[] credentialId = authenticator.getAttestedCredentialData().getCredentialId();
            credentials.add(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credentialId, authenticator.getTransports()));
        }

        PublicKeyCredentialRpEntity relyingParty = new PublicKeyCredentialRpEntity(getEffectiveRpId(request), rpName, rpIcon);
        if (challenge == null) {
            challenge = challengeRepository.loadOrGenerateChallenge(request);
        } else {
            challengeRepository.saveChallenge(challenge, request);
        }

        return new AttestationOptions(relyingParty, user, challenge, pubKeyCredParams, registrationTimeout,
                credentials, registrationExtensions);
    }

    public AssertionOptions getAssertionOptions(HttpServletRequest request, String username, Challenge challenge) {

        Collection<? extends WebAuthnAuthenticator> authenticators;
        try {
            authenticators = authenticatorService.loadAuthenticatorsByPrincipal(username);
        } catch (UsernameNotFoundException e) {
            authenticators = Collections.emptyList();
        }

        String effectiveRpId = getEffectiveRpId(request);

        List<PublicKeyCredentialDescriptor> credentials = new ArrayList<>();
        for (WebAuthnAuthenticator authenticator : authenticators) {
            credentials.add(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, authenticator.getAttestedCredentialData().getCredentialId(), authenticator.getTransports()));
        }
        if (challenge == null) {
            challenge = challengeRepository.loadOrGenerateChallenge(request);
        } else {
            challengeRepository.saveChallenge(challenge, request);
        }

        return new AssertionOptions(challenge, authenticationTimeout, effectiveRpId, credentials, authenticationExtensions);
    }

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

    @Override
    public String getRpIcon() {
        return rpIcon;
    }

    @Override
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
        Assert.isTrue(registrationTimeout >= 0, "registrationTimeout must be within unsigned long.");
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

    static class DefaultPublicKeyCredentialUserEntityService implements PublicKeyCredentialUserEntityService {

        @Override
        public PublicKeyCredentialUserEntity loadUserByUsername(String username) {
            return new PublicKeyCredentialUserEntity(
                    username.getBytes(StandardCharsets.UTF_8),
                    username,
                    username
            );
        }
    }

}
