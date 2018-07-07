package net.sharplab.springframework.security.webauthn;

import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsImpl;
import org.junit.Test;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class WebAuthnMultiFactorAuthenticationProviderTest {

    @Test
    public void authenticate_with_singleFactorAuthenticationAllowedOption_false_test(){
        AuthenticationProvider delegatedAuthenticationProvider = mock(AuthenticationProvider.class);
        when(delegatedAuthenticationProvider.supports(any())).thenReturn(true);
        when(delegatedAuthenticationProvider.authenticate(any()))
                .thenReturn(new UsernamePasswordAuthenticationToken(
                        "principal",
                        "credentials",
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_DUMMY"))
                ));

        WebAuthnMultiFactorAuthenticationProvider provider = new WebAuthnMultiFactorAuthenticationProvider(delegatedAuthenticationProvider);
        provider.setSingleFactorAuthenticationAllowed(false);
        Authentication result = provider.authenticate(new UsernamePasswordAuthenticationToken("dummy", "dummy"));

        assertThat(provider.isSingleFactorAuthenticationAllowed()).isFalse();
        assertThat(result).isInstanceOf(MultiFactorAuthenticationToken.class);
        assertThat(result.getPrincipal()).isEqualTo("principal");
        assertThat(result.getCredentials()).isEqualTo("credentials");
        assertThat(result.getAuthorities()).isEmpty();

    }

    @Test
    public void authenticate_with_singleFactorAuthenticationAllowedOption_true_test(){
        AuthenticationProvider delegatedAuthenticationProvider = mock(AuthenticationProvider.class);
        WebAuthnUserDetails userDetails = new WebAuthnUserDetailsImpl("dummy", "dummy", Collections.emptyList(), true, Collections.emptyList());
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, Collections.emptyList());
        authenticationToken.setDetails(userDetails);
        when(delegatedAuthenticationProvider.supports(any())).thenReturn(true);
        when(delegatedAuthenticationProvider.authenticate(any()))
                .thenReturn(authenticationToken);

        WebAuthnMultiFactorAuthenticationProvider provider = new WebAuthnMultiFactorAuthenticationProvider(delegatedAuthenticationProvider);
        provider.setSingleFactorAuthenticationAllowed(true);
        Authentication result = provider.authenticate(new UsernamePasswordAuthenticationToken("dummy", "dummy"));

        assertThat(provider.isSingleFactorAuthenticationAllowed()).isTrue();
        assertThat(result).isEqualTo(result);
    }

    @Test(expected = IllegalArgumentException.class)
    public void authenticate_with_invalid_AuthenticationToken_test(){
        AuthenticationProvider delegatedAuthenticationProvider = mock(AuthenticationProvider.class);
        when(delegatedAuthenticationProvider.supports(any())).thenReturn(false);

        WebAuthnMultiFactorAuthenticationProvider provider = new WebAuthnMultiFactorAuthenticationProvider(delegatedAuthenticationProvider);
        provider.setSingleFactorAuthenticationAllowed(true);
        provider.authenticate(new TestingAuthenticationToken("dummy", "dummy"));
    }
}
