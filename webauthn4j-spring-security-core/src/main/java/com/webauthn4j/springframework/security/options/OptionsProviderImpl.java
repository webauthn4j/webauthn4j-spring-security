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
import com.webauthn4j.springframework.security.WebAuthnProcessingFilter;
import com.webauthn4j.springframework.security.WebAuthnUserEntityProvider;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.endpoint.Parameters;
import com.webauthn4j.springframework.security.util.internal.ServletUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
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
    private AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput<?>> registrationExtensions = new AuthenticationExtensionsClientInputs<>();
    private AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput<?>> authenticationExtensions = new AuthenticationExtensionsClientInputs<>();

    private String usernameParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY;
    private String passwordParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY;
    private String credentialIdParameter = WebAuthnProcessingFilter.SPRING_SECURITY_FORM_CREDENTIAL_ID_KEY;
    private String clientDataJSONParameter = WebAuthnProcessingFilter.SPRING_SECURITY_FORM_CLIENT_DATA_JSON_KEY;
    private String authenticatorDataParameter = WebAuthnProcessingFilter.SPRING_SECURITY_FORM_AUTHENTICATOR_DATA_KEY;
    private String signatureParameter = WebAuthnProcessingFilter.SPRING_SECURITY_FORM_SIGNATURE_KEY;
    private String clientExtensionsJSONParameter = WebAuthnProcessingFilter.SPRING_SECURITY_FORM_CLIENT_EXTENSIONS_JSON_KEY;

    private final WebAuthnAuthenticatorService authenticatorService;
    private final WebAuthnUserEntityProvider webAuthnUserEntityProvider;
    private final ChallengeRepository challengeRepository;

    // ~ Constructors
    // ===================================================================================================

    public OptionsProviderImpl(WebAuthnAuthenticatorService authenticatorService, WebAuthnUserEntityProvider webAuthnUserEntityProvider, ChallengeRepository challengeRepository) {

        Assert.notNull(authenticatorService, "authenticatorService must not be null");
        Assert.notNull(webAuthnUserEntityProvider, "webAuthnUserHandleProvider must not be null");
        Assert.notNull(challengeRepository, "challengeRepository must not be null");

        this.authenticatorService = authenticatorService;
        this.webAuthnUserEntityProvider = webAuthnUserEntityProvider;
        this.challengeRepository = challengeRepository;
    }

    public OptionsProviderImpl(WebAuthnAuthenticatorService authenticatorService, ChallengeRepository challengeRepository) {
        this(authenticatorService, new DefaultWebAuthnUserEntityProvider(), challengeRepository);
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
            user = webAuthnUserEntityProvider.provide(username);
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

        List<String> credentials = new ArrayList<>();
        for (WebAuthnAuthenticator authenticator : authenticators) {
            String credentialId = Base64UrlUtil.encodeToString(authenticator.getAttestedCredentialData().getCredentialId());
            credentials.add(credentialId);
        }
        if (challenge == null) {
            challenge = challengeRepository.loadOrGenerateChallenge(request);
        } else {
            challengeRepository.saveChallenge(challenge, request);
        }
        Parameters parameters
                = new Parameters(usernameParameter, passwordParameter,
                credentialIdParameter, clientDataJSONParameter, authenticatorDataParameter, signatureParameter, clientExtensionsJSONParameter);

        return new AssertionOptions(challenge, authenticationTimeout, effectiveRpId, credentials, authenticationExtensions, parameters);
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

    public AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput<?>> getRegistrationExtensions() {
        return registrationExtensions;
    }

    public void setRegistrationExtensions(AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput<?>> registrationExtensions) {
        this.registrationExtensions = registrationExtensions;
    }

    public AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput<?>> getAuthenticationExtensions() {
        return authenticationExtensions;
    }

    public void setAuthenticationExtensions(AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput<?>> authenticationExtensions) {
        this.authenticationExtensions = authenticationExtensions;
    }

    public String getUsernameParameter() {
        return usernameParameter;
    }

    public void setUsernameParameter(String usernameParameter) {
        Assert.hasText(usernameParameter, "usernameParameter must not be empty or null");
        this.usernameParameter = usernameParameter;
    }

    public String getPasswordParameter() {
        return passwordParameter;
    }

    public void setPasswordParameter(String passwordParameter) {
        Assert.hasText(passwordParameter, "passwordParameter must not be empty or null");
        this.passwordParameter = passwordParameter;
    }

    public String getCredentialIdParameter() {
        return credentialIdParameter;
    }

    public void setCredentialIdParameter(String credentialIdParameter) {
        Assert.hasText(credentialIdParameter, "credentialIdParameter must not be empty or null");
        this.credentialIdParameter = credentialIdParameter;
    }

    public String getClientDataJSONParameter() {
        return clientDataJSONParameter;
    }

    public void setClientDataJSONParameter(String clientDataJSONParameter) {
        Assert.hasText(clientDataJSONParameter, "clientDataJSONParameter must not be empty or null");
        this.clientDataJSONParameter = clientDataJSONParameter;
    }

    public String getAuthenticatorDataParameter() {
        return authenticatorDataParameter;
    }

    public void setAuthenticatorDataParameter(String authenticatorDataParameter) {
        Assert.hasText(authenticatorDataParameter, "authenticatorDataParameter must not be empty or null");
        this.authenticatorDataParameter = authenticatorDataParameter;
    }

    public String getSignatureParameter() {
        return signatureParameter;
    }

    public void setSignatureParameter(String signatureParameter) {
        Assert.hasText(signatureParameter, "signatureParameter must not be empty or null");
        this.signatureParameter = signatureParameter;
    }

    public String getClientExtensionsJSONParameter() {
        return clientExtensionsJSONParameter;
    }

    public void setClientExtensionsJSONParameter(String clientExtensionsJSONParameter) {
        Assert.hasText(clientExtensionsJSONParameter, "clientExtensionsJSONParameter must not be empty or null");
        this.clientExtensionsJSONParameter = clientExtensionsJSONParameter;
    }

    static class DefaultWebAuthnUserEntityProvider implements WebAuthnUserEntityProvider {

        @Override
        public PublicKeyCredentialUserEntity provide(String username) {
            return new PublicKeyCredentialUserEntity(
                    username.getBytes(StandardCharsets.UTF_8),
                    username,
                    username
            );
        }
    }

}
