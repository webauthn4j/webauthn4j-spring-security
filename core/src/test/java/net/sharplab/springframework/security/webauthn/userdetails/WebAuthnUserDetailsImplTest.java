package net.sharplab.springframework.security.webauthn.userdetails;


import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnUserDetailsImplTest {

    @Test
    public void getter_setter_test() {
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
        WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
                new byte[0],
                "dummy",
                "dummy",
                Collections.singletonList(authenticator),
                Collections.singletonList(grantedAuthority));

        userDetails.setSingleFactorAuthenticationAllowed(true);
        assertThat(userDetails.isSingleFactorAuthenticationAllowed()).isTrue();
        assertThat(userDetails.getAuthenticators()).isEqualTo(Collections.singletonList(authenticator));
    }

}
