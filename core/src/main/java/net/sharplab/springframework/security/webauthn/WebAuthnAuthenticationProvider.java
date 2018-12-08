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

package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import net.sharplab.springframework.security.webauthn.exception.*;
import net.sharplab.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * WebAuthnAuthenticationProvider
 */
public class WebAuthnAuthenticationProvider implements AuthenticationProvider {

    protected final Log logger = LogFactory.getLog(getClass());

    //~ Instance fields
    // ================================================================================================
    protected MessageSourceAccessor messages = SpringSecurityWebAuthnMessageSource.getAccessor();
    private WebAuthnUserDetailsService userDetailsService;
    private WebAuthnAuthenticatorService authenticatorService;
    private WebAuthnAuthenticationContextValidator authenticationContextValidator;
    private boolean forcePrincipalAsString = false;
    private boolean hideCredentialIdNotFoundExceptions = true;
    private UserDetailsChecker preAuthenticationChecks = new DefaultPreAuthenticationChecks();
    private UserDetailsChecker postAuthenticationChecks = new DefaultPostAuthenticationChecks();
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    private List<String> expectedAuthenticationExtensionIds = Collections.emptyList();

    public WebAuthnAuthenticationProvider(
            WebAuthnUserDetailsService userDetailsService,
            WebAuthnAuthenticatorService authenticatorService,
            WebAuthnAuthenticationContextValidator authenticationContextValidator) {
        this.userDetailsService = userDetailsService;
        this.authenticatorService = authenticatorService;
        this.authenticationContextValidator = authenticationContextValidator;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Authentication authenticate(Authentication authentication) {
        if (!supports(authentication.getClass())) {
            throw new IllegalArgumentException("Only WebAuthnAssertionAuthenticationToken is supported, " + authentication.getClass() + " was attempted");
        }

        WebAuthnAssertionAuthenticationToken authenticationToken = (WebAuthnAssertionAuthenticationToken) authentication;

        WebAuthnAuthenticationRequest credentials = authenticationToken.getCredentials();
        if (credentials == null) {
            logger.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException(messages.getMessage(
                    "WebAuthnAuthenticationContextValidator.badCredentials",
                    "Bad credentials"));
        }

        byte[] credentialId = credentials.getCredentialId();

        WebAuthnUserDetails user = retrieveWebAuthnUserDetails(credentialId);
        Authenticator authenticator = user.getAuthenticators().stream()
                .filter(item -> Arrays.equals(item.getAttestedCredentialData().getCredentialId(), credentialId))
                .findFirst()
                .orElse(null);

        preAuthenticationChecks.check(user);
        doAuthenticate(authenticationToken, authenticator, user);
        postAuthenticationChecks.check(user);

        //noinspection ConstantConditions
        authenticatorService.updateCounter(credentialId, authenticator.getCounter());

        Serializable principalToReturn = user;

        if (forcePrincipalAsString) {
            principalToReturn = user.getUsername();
        }

        WebAuthnAuthenticationToken result = new WebAuthnAuthenticationToken(
                principalToReturn, authenticationToken.getCredentials(),
                authoritiesMapper.mapAuthorities(user.getAuthorities()));
        result.setDetails(authenticationToken.getDetails());

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return WebAuthnAssertionAuthenticationToken.class.isAssignableFrom(authentication);
    }

    void doAuthenticate(WebAuthnAssertionAuthenticationToken authenticationToken, Authenticator authenticator, WebAuthnUserDetails user) {

        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isUserVerified = currentAuthentication != null && Objects.equals(currentAuthentication.getName(), user.getUsername());
        boolean userVerificationRequired = !isUserVerified; // If user is not verified, user verification is required.

        WebAuthnAuthenticationRequest credentials = authenticationToken.getCredentials();
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                credentials.getCredentialId(),
                credentials.getClientDataJSON(),
                credentials.getAuthenticatorData(),
                credentials.getSignature(),
                credentials.getClientExtensionsJSON(),
                credentials.getServerProperty(),
                userVerificationRequired,
                expectedAuthenticationExtensionIds
        );

        try {
            authenticationContextValidator.validate(authenticationContext, authenticator);
        } catch (RuntimeException e) {
            throw wrapWithAuthenticationException(e);
        }

    }

    public boolean isForcePrincipalAsString() {
        return forcePrincipalAsString;
    }

    public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
        this.forcePrincipalAsString = forcePrincipalAsString;
    }

    public List<String> getExpectedAuthenticationExtensionIds() {
        return expectedAuthenticationExtensionIds;
    }

    public void setExpectedAuthenticationExtensionIds(List<String> expectedAuthenticationExtensionIds) {
        this.expectedAuthenticationExtensionIds = expectedAuthenticationExtensionIds;
    }

    public boolean isHideCredentialIdNotFoundExceptions() {
        return hideCredentialIdNotFoundExceptions;
    }

    /**
     * By default the <code>WebAuthnAuthenticationProvider</code> throws a
     * <code>BadCredentialsException</code> if a credentialId is not found or the credential is
     * incorrect. Setting this property to <code>false</code> will cause
     * <code>CredentialIdNotFoundException</code>s to be thrown instead for the former. Note
     * this is considered less secure than throwing <code>BadCredentialsException</code>
     * for both exceptions.
     *
     * @param hideCredentialIdNotFoundExceptions set to <code>false</code> if you wish
     *                                           <code>CredentialIdNotFoundException</code>s to be thrown instead of the non-specific
     *                                           <code>BadCredentialsException</code> (defaults to <code>true</code>)
     */
    public void setHideCredentialIdNotFoundExceptions(boolean hideCredentialIdNotFoundExceptions) {
        this.hideCredentialIdNotFoundExceptions = hideCredentialIdNotFoundExceptions;
    }

    protected WebAuthnUserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public void setUserDetailsService(WebAuthnUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    protected UserDetailsChecker getPreAuthenticationChecks() {
        return preAuthenticationChecks;
    }

    /**
     * Sets the policy will be used to verify the status of the loaded
     * <tt>UserDetails</tt> <em>before</em> validation of the credentials takes place.
     *
     * @param preAuthenticationChecks strategy to be invoked prior to authentication.
     */
    public void setPreAuthenticationChecks(UserDetailsChecker preAuthenticationChecks) {
        this.preAuthenticationChecks = preAuthenticationChecks;
    }

    protected UserDetailsChecker getPostAuthenticationChecks() {
        return postAuthenticationChecks;
    }

    public void setPostAuthenticationChecks(UserDetailsChecker postAuthenticationChecks) {
        this.postAuthenticationChecks = postAuthenticationChecks;
    }

    WebAuthnUserDetails retrieveWebAuthnUserDetails(byte[] credentialId) {
        WebAuthnUserDetails user;
        try {
            user = userDetailsService.loadUserByCredentialId(credentialId);
        } catch (CredentialIdNotFoundException notFound) {
            if (hideCredentialIdNotFoundExceptions) {
                throw new BadCredentialsException(messages.getMessage(
                        "WebAuthnAuthenticationProvider.badCredentials",
                        "Bad credentials"));
            } else {
                throw notFound;
            }
        } catch (Exception repositoryProblem) {
            throw new InternalAuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
        }

        if (user == null) {
            throw new InternalAuthenticationServiceException(
                    "UserDetailsService returned null, which is an interface contract violation");
        }
        return user;
    }

    @SuppressWarnings("squid:S3776")
    RuntimeException wrapWithAuthenticationException(RuntimeException e) {
        if (e instanceof com.webauthn4j.validator.exception.BadAlgorithmException) {
            return new BadAlgorithmException("Bad algorithm", e);
        } else if (e instanceof com.webauthn4j.validator.exception.BadAttestationStatementException) {
            return new BadAttestationStatementException("Bad attestation statement", e);
        } else if (e instanceof com.webauthn4j.validator.exception.BadChallengeException) {
            return new BadChallengeException("Bad challenge", e);
        } else if (e instanceof com.webauthn4j.validator.exception.BadOriginException) {
            return new BadOriginException("Bad origin", e);
        } else if (e instanceof com.webauthn4j.validator.exception.BadRpIdException) {
            return new BadRpIdException("Bad rpId", e);
        } else if (e instanceof com.webauthn4j.validator.exception.BadSignatureException) {
            return new BadSignatureException("Bad signature", e);
        } else if (e instanceof com.webauthn4j.validator.exception.CertificateException) {
            return new CertificateException("Certificate error", e);
        } else if (e instanceof com.webauthn4j.validator.exception.ConstraintViolationException) {
            return new ConstraintViolationException("Constraint violation error", e);
        } else if (e instanceof com.webauthn4j.validator.exception.MaliciousCounterValueException) {
            return new MaliciousCounterValueException("Malicious counter value is detected. Cloned authenticators exist in parallel.", e);
        } else if (e instanceof com.webauthn4j.validator.exception.MaliciousDataException) {
            return new MaliciousDataException("Bad client data type", e);
        } else if (e instanceof com.webauthn4j.validator.exception.MissingChallengeException) {
            return new MissingChallengeException("Missing challenge error", e);
        } else if (e instanceof com.webauthn4j.validator.exception.SelfAttestationProhibitedException) {
            return new SelfAttestationProhibitedException("Self attestation is specified while prohibited", e);
        } else if (e instanceof com.webauthn4j.validator.exception.TokenBindingException) {
            return new TokenBindingException("Token binding error", e);
        } else if (e instanceof com.webauthn4j.validator.exception.UnexpectedExtensionException) {
            return new UnexpectedExtensionException("Unexpected extension is contained", e);
        } else if (e instanceof com.webauthn4j.validator.exception.UnsupportedAttestationFormatException) {
            return new UnsupportedAttestationFormatException("Unsupported attestation format error", e);
        } else if (e instanceof com.webauthn4j.validator.exception.UserNotPresentException) {
            return new UserNotPresentException("User not verified", e);
        } else if (e instanceof com.webauthn4j.validator.exception.UserNotVerifiedException) {
            return new UserNotVerifiedException("User not verified", e);
        } else if (e instanceof com.webauthn4j.validator.exception.ValidationException) {
            return new AuthenticationServiceException("WebAuthn validation error", e);
        }
        return e;
    }

    private class DefaultPreAuthenticationChecks implements UserDetailsChecker {
        @Override
        public void check(UserDetails user) {
            if (!user.isAccountNonLocked()) {
                logger.debug("User account is locked");

                throw new LockedException(messages.getMessage(
                        "WebAuthnAuthenticationProvider.locked",
                        "User account is locked"));
            }

            if (!user.isEnabled()) {
                logger.debug("User account is disabled");

                throw new DisabledException(messages.getMessage(
                        "WebAuthnAuthenticationProvider.disabled",
                        "User is disabled"));
            }

            if (!user.isAccountNonExpired()) {
                logger.debug("User account is expired");

                throw new AccountExpiredException(messages.getMessage(
                        "WebAuthnAuthenticationProvider.expired",
                        "User account has expired"));
            }
        }
    }

    private class DefaultPostAuthenticationChecks implements UserDetailsChecker {
        @Override
        public void check(UserDetails user) {
            if (!user.isCredentialsNonExpired()) {
                logger.debug("User account credentials have expired");

                throw new CredentialsExpiredException(messages.getMessage(
                        "WebAuthnAuthenticationProvider.credentialsExpired",
                        "User credentials have expired"));
            }
        }
    }
}
