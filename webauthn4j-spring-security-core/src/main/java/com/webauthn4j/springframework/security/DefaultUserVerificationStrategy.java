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

package com.webauthn4j.springframework.security;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class DefaultUserVerificationStrategy implements UserVerificationStrategy {

    private AuthenticationTrustResolver trustResolver;

    public DefaultUserVerificationStrategy(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }

    public DefaultUserVerificationStrategy(){
        this(new AuthenticationTrustResolverImpl());
    }

    @Override
    public boolean isUserVerificationRequired() {
        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if(currentAuthentication == null){
            return true;
        }
        if(trustResolver.isAnonymous(currentAuthentication)){
            return true;
        }
        return !currentAuthentication.isAuthenticated();
    }

    public AuthenticationTrustResolver getTrustResolver() {
        return trustResolver;
    }

    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }
}
