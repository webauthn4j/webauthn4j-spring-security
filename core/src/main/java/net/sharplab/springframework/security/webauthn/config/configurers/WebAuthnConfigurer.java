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

package net.sharplab.springframework.security.webauthn.config.configurers;

import com.webauthn4j.request.PublicKeyCredentialParameters;
import com.webauthn4j.request.PublicKeyCredentialType;
import com.webauthn4j.response.attestation.statement.COSEAlgorithmIdentifier;
import net.sharplab.springframework.security.webauthn.endpoint.OptionsProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.util.Assert;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class WebAuthnConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<WebAuthnConfigurer<H>, H> {

    private final WebAuthnConfigurer<H>.PublicKeyCredParamsConfig publicKeyCredParamsConfig = new WebAuthnConfigurer<H>.PublicKeyCredParamsConfig();
    private OptionsProvider optionsProvider;
    private String rpId = null;
    private String rpName = null;
    private String rpIcon = null;
    private BigInteger registrationTimeout;
    private BigInteger authenticationTimeout;

    public static WebAuthnConfigurer<HttpSecurity> webAuthn() {
        return new WebAuthnConfigurer<>();
    }

    @Override
    public void init(H http) throws Exception {
        super.init(http);

        if (optionsProvider == null) {
            optionsProvider = WebAuthnConfigurerUtil.getOptionsProvider(http);
        }
        http.setSharedObject(OptionsProvider.class, optionsProvider);
    }

    @Override
    public void configure(H http) throws Exception {
        super.configure(http);

        if (rpId != null) {
            optionsProvider.setRpId(rpId);
        }
        if (rpName != null) {
            optionsProvider.setRpName(rpName);
        }
        if (rpIcon != null) {
            optionsProvider.setRpIcon(rpIcon);
        }
        optionsProvider.getPubKeyCredParams().addAll(publicKeyCredParamsConfig.publicKeyCredentialParameters);
        if (registrationTimeout != null) {
            optionsProvider.setRegistrationTimeout(registrationTimeout);
        }
        if (authenticationTimeout != null) {
            optionsProvider.setAuthenticationTimeout(authenticationTimeout);
        }
    }

    public WebAuthnConfigurer<H> rpId(String rpId) {
        Assert.hasText(rpId, "rpId parameter must not be null or empty");
        this.rpId = rpId;
        return this;
    }

    public WebAuthnConfigurer<H> rpName(String rpName) {
        Assert.hasText(rpName, "rpName parameter must not be null or empty");
        this.rpName = rpName;
        return this;
    }

    public WebAuthnConfigurer<H> rpIcon(String rpIcon) {
        Assert.hasText(rpIcon, "rpIcon parameter must not be null or empty");
        this.rpIcon = rpIcon;
        return this;
    }

    public WebAuthnConfigurer<H>.PublicKeyCredParamsConfig publicKeyCredParams() {
        return this.publicKeyCredParamsConfig;
    }

    public WebAuthnConfigurer<H> registrationTimeout(BigInteger registrationTimeout) {
        this.registrationTimeout = registrationTimeout;
        return this;
    }

    public WebAuthnConfigurer<H> authenticationTimeout(BigInteger authenticationTimeout) {
        this.authenticationTimeout = authenticationTimeout;
        return this;
    }


    public class PublicKeyCredParamsConfig {

        private List<PublicKeyCredentialParameters> publicKeyCredentialParameters = new ArrayList<>();

        public WebAuthnConfigurer.PublicKeyCredParamsConfig addPublicKeyCredParams(PublicKeyCredentialType type, COSEAlgorithmIdentifier alg) {
            publicKeyCredentialParameters.add(new PublicKeyCredentialParameters(type, alg));
            return this;
        }

        public WebAuthnConfigurer<H> and() {
            return WebAuthnConfigurer.this;
        }

    }
}
