package net.sharplab.springframework.security.webauthn.config.configurers;

import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import net.sharplab.springframework.security.webauthn.WebAuthnAuthenticationProvider;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.util.Assert;

public class WebAuthnAuthenticationProviderConfigurer<B extends ProviderManagerBuilder<B>, U extends WebAuthnUserDetailsService>
        extends SecurityConfigurerAdapter<AuthenticationManager, B> {

    //~ Instance fields
    // ================================================================================================
    private U userDetailsService;
    private WebAuthnAuthenticationContextValidator authenticationContextValidator = new WebAuthnAuthenticationContextValidator();

    /**
     * Constructor
     * @param userDetailsService {@link WebAuthnUserDetailsService}
     */
    public WebAuthnAuthenticationProviderConfigurer(U userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public void configure(B builder) {
        WebAuthnAuthenticationProvider authenticationProvider =
                new WebAuthnAuthenticationProvider(userDetailsService, authenticationContextValidator);
        authenticationProvider = postProcess(authenticationProvider);
        builder.authenticationProvider(authenticationProvider);
    }

    public WebAuthnAuthenticationProviderConfigurer<B, U> authenticationContextValidator(WebAuthnAuthenticationContextValidator authenticationContextValidator) {
        Assert.notNull(authenticationContextValidator, "authenticationContextValidator cannot be null");
        this.authenticationContextValidator = authenticationContextValidator;
        return this;
    }


}
