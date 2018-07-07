package net.sharplab.springframework.security.webauthn;

import net.sharplab.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class WebAuthnAssertionAuthenticationTokenTest {

    @Test(expected = IllegalArgumentException.class)
    public void setAuthenticated_with_true_test(){
        WebAuthnAuthenticationRequest request = mock(WebAuthnAuthenticationRequest.class);
        WebAuthnAssertionAuthenticationToken token = new WebAuthnAssertionAuthenticationToken(request);
        token.setAuthenticated(true);
    }

    @Test
    public void setAuthenticated_with_false_test(){
        WebAuthnAuthenticationRequest request = mock(WebAuthnAuthenticationRequest.class);
        WebAuthnAssertionAuthenticationToken token = new WebAuthnAssertionAuthenticationToken(request);
        token.setAuthenticated(false);
    }

    @Test
    public void eraseCredentials_test(){
        WebAuthnAuthenticationRequest request = mock(WebAuthnAuthenticationRequest.class);
        WebAuthnAssertionAuthenticationToken token = new WebAuthnAssertionAuthenticationToken(request);
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();
    }

    @Test
    public void equals_hashCode_test(){
        WebAuthnAuthenticationRequest request = mock(WebAuthnAuthenticationRequest.class);
        WebAuthnAssertionAuthenticationToken tokenA = new WebAuthnAssertionAuthenticationToken(request);
        WebAuthnAssertionAuthenticationToken tokenB = new WebAuthnAssertionAuthenticationToken(request);

        assertThat(tokenA).isEqualTo(tokenB);
        assertThat(tokenA).hasSameHashCodeAs(tokenB);
    }
}
