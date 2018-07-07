package net.sharplab.springframework.security.webauthn.config.configurers;

import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import net.sharplab.springframework.security.webauthn.WebAuthnAuthenticationProvider;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.util.Assert;

public class WebAuthnAuthenticationConfigurer<B extends ProviderManagerBuilder<B>, U extends WebAuthnUserDetailsService, A extends WebAuthnAuthenticatorService>
        extends SecurityConfigurerAdapter<AuthenticationManager, B> {

    //~ Instance fields
    // ================================================================================================
    private U userDetailsService;
    private A authenticatorService;
    private WebAuthnAuthenticationContextValidator authenticationContextValidator = new WebAuthnAuthenticationContextValidator();

    /**
     * Constructor
     * @param userDetailsService {@link WebAuthnUserDetailsService}
     * @param authenticatorService {@link WebAuthnAuthenticatorService}
     */
    public WebAuthnAuthenticationConfigurer(U userDetailsService, A authenticatorService) {
        this.userDetailsService = userDetailsService;
        this.authenticatorService = authenticatorService;
    }

    @Override
    public void configure(B builder) {
        WebAuthnAuthenticationProvider authenticationProvider =
                new WebAuthnAuthenticationProvider(userDetailsService, authenticatorService ,authenticationContextValidator);
        authenticationProvider = postProcess(authenticationProvider);
        builder.authenticationProvider(authenticationProvider);
    }

    public WebAuthnAuthenticationConfigurer<B, U, A> authenticationContextValidator(WebAuthnAuthenticationContextValidator authenticationContextValidator) {
        Assert.notNull(authenticationContextValidator, "authenticationContextValidator cannot be null");
        this.authenticationContextValidator = authenticationContextValidator;
        return this;
    }


}
