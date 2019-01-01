/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.registry.Registry;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.SpringSecurityMessageSource;

import javax.servlet.http.HttpServletRequest;

public class OptionsEndpointFilter extends ServerEndpointFilterBase {

    /**
     * Default name of path suffix which will validate this filter.
     */
    public static final String FILTER_URL = "/webauthn/options";

    //~ Instance fields
    // ================================================================================================
    /**
     * Url this filter should get activated on.
     */
    private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private OptionsProvider optionsProvider;

    public OptionsEndpointFilter(OptionsProvider optionsProvider, Registry registry) {
        super(FILTER_URL, registry);
        this.optionsProvider = optionsProvider;
    }


    @Override
    protected ServerResponse processRequest(HttpServletRequest request) {
        String loginUsername = getLoginUsername();
        AttestationOptions attestationOptions = optionsProvider.getAttestationOptions(request, loginUsername, null);
        AssertionOptions assertionOptions = optionsProvider.getAssertionOptions(request, loginUsername, null);
        return new Options(
                attestationOptions.getRelyingParty(),
                attestationOptions.getUser(),
                attestationOptions.getChallenge(),
                attestationOptions.getPubKeyCredParams(),
                attestationOptions.getRegistrationTimeout(),
                assertionOptions.getAuthenticationTimeout(),
                attestationOptions.getCredentials(),
                attestationOptions.getRegistrationExtensions(),
                assertionOptions.getAuthenticationExtensions(),
                assertionOptions.getParameters()
                );
    }

    /**
     * The filter will be used in case the URL of the request contains the FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    private boolean processFilter(HttpServletRequest request) {
        return (request.getRequestURI().contains(filterProcessesUrl));
    }

}
