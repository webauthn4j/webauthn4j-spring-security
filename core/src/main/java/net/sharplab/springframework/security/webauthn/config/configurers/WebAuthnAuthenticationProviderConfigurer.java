package net.sharplab.springframework.security.webauthn.config.configurers;

import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import net.sharplab.springframework.security.webauthn.WebAuthnAuthenticationProvider;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;

public class WebAuthnAuthenticationProviderConfigurer<
        B extends ProviderManagerBuilder<B>,
        U extends WebAuthnUserDetailsService,
        A extends WebAuthnAuthenticatorService,
        V extends WebAuthnAuthenticationContextValidator>
        extends SecurityConfigurerAdapter<AuthenticationManager, B> {

    //~ Instance fields
    // ================================================================================================
    private U userDetailsService;
    private A authenticatorService;
    private WebAuthnAuthenticationContextValidator authenticationContextValidator;

    /**
     * Constructor
     *
     * @param userDetailsService   {@link WebAuthnUserDetailsService}
     * @param authenticatorService {@link WebAuthnAuthenticatorService}
     */
    public WebAuthnAuthenticationProviderConfigurer(U userDetailsService, A authenticatorService, V authenticationContextValidator) {
        this.userDetailsService = userDetailsService;
        this.authenticatorService = authenticatorService;
        this.authenticationContextValidator = authenticationContextValidator;
    }

    @Override
    public void configure(B builder) {
        WebAuthnAuthenticationProvider authenticationProvider =
                new WebAuthnAuthenticationProvider(userDetailsService, authenticatorService, authenticationContextValidator);
        authenticationProvider = postProcess(authenticationProvider);
        builder.authenticationProvider(authenticationProvider);
    }

}
