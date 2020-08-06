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

package com.webauthn4j.springframework.security.fido.server.endpoint;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.options.OptionsProvider;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * FIDO Server Endpoint for attestation options processing
 * With this endpoint, non-authorized user can observe requested username existence and his/her credentialId list.
 */
public class FidoServerAttestationOptionsEndpointFilter extends ServerEndpointFilterBase {

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/attestation/options";

    //~ Instance fields
    // ================================================================================================

    private final OptionsProvider optionsProvider;
    private final ChallengeRepository challengeRepository;

    public FidoServerAttestationOptionsEndpointFilter(ObjectConverter objectConverter, OptionsProvider optionsProvider, ChallengeRepository challengeRepository) {
        super(FILTER_URL, objectConverter);
        this.optionsProvider = optionsProvider;
        this.challengeRepository = challengeRepository;
        checkConfig();
    }

    @Override
    public void afterPropertiesSet() {
        super.afterPropertiesSet();
        checkConfig();
    }

    @SuppressWarnings("squid:S2177")
    private void checkConfig() {
        Assert.notNull(optionsProvider, "optionsProvider must not be null");
    }

    @Override
    protected ServerResponse processRequest(HttpServletRequest request) {
        InputStream inputStream;
        try {
            inputStream = request.getInputStream();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        try {
            ServerPublicKeyCredentialCreationOptionsRequest serverRequest = objectConverter.getJsonConverter()
                    .readValue(inputStream, ServerPublicKeyCredentialCreationOptionsRequest.class);
            String username = serverRequest.getUsername();
            String displayName = serverRequest.getDisplayName();
            Challenge challenge = serverEndpointFilterUtil.encodeUsername(new DefaultChallenge(), username);
            challengeRepository.saveChallenge(challenge, request);
            PublicKeyCredentialCreationOptions attestationOptions = optionsProvider.getAttestationOptions(request, username);
            String userHandle;
            if (attestationOptions.getUser() == null) {
                userHandle = Base64UrlUtil.encodeToString(generateUserHandle());
            } else {
                userHandle = Base64UrlUtil.encodeToString(attestationOptions.getUser().getId());
            }
            ServerPublicKeyCredentialUserEntity user = new ServerPublicKeyCredentialUserEntity(userHandle, username, displayName, null);
            List<ServerPublicKeyCredentialDescriptor> credentials =
                    attestationOptions.getExcludeCredentials().stream()
                            .map(credential -> new ServerPublicKeyCredentialDescriptor(credential.getType(), Base64UrlUtil.encodeToString(credential.getId()), credential.getTransports()))
                            .collect(Collectors.toList());
            AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> authenticationExtensionsClientInputs;
            if (serverRequest.getExtensions() != null) {
                authenticationExtensionsClientInputs = serverRequest.getExtensions();
            } else {
                authenticationExtensionsClientInputs = attestationOptions.getExtensions();
            }

            return new ServerPublicKeyCredentialCreationOptionsResponse(
                    attestationOptions.getRp(),
                    user,
                    Base64UrlUtil.encodeToString(attestationOptions.getChallenge().getValue()),
                    attestationOptions.getPubKeyCredParams(),
                    attestationOptions.getTimeout(),
                    credentials,
                    serverRequest.getAuthenticatorSelection(),
                    serverRequest.getAttestation(),
                    authenticationExtensionsClientInputs);
        }
        catch (DataConversionException e){
            throw new com.webauthn4j.springframework.security.exception.DataConversionException("Failed to convert data", e);
        }
    }


    private byte[] generateUserHandle() {
        UUID uuid = UUID.randomUUID();
        long hi = uuid.getMostSignificantBits();
        long lo = uuid.getLeastSignificantBits();
        return ByteBuffer.allocate(16).putLong(hi).putLong(lo).array();
    }

}
