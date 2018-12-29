package net.sharplab.springframework.security.webauthn.request;

import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.client.ClientDataType;
import com.webauthn4j.response.client.Origin;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnAuthenticationRequestTest {

    private Registry registry = new Registry();

    @Test
    public void equals_hashCode_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] clientDataJSON = TestUtil.createClientDataJSON(ClientDataType.GET);
        byte[] authenticatorData = new AuthenticatorDataConverter(registry).convert(TestUtil.createAuthenticatorData());
        WebAuthnAuthenticationRequest requestA = new WebAuthnAuthenticationRequest(
                new byte[]{0x01, 0x23},
                clientDataJSON,
                authenticatorData,
                new byte[]{0x45, 0x56},
                "",
                new ServerProperty(
                        new Origin("https://example.com"),
                        "example.com",
                        challenge,
                        new byte[]{0x43, 0x21}
                )
        );
        WebAuthnAuthenticationRequest requestB = new WebAuthnAuthenticationRequest(
                new byte[]{0x01, 0x23},
                clientDataJSON,
                authenticatorData,
                new byte[]{0x45, 0x56},
                "",
                new ServerProperty(
                        new Origin("https://example.com"),
                        "example.com",
                        challenge,
                        new byte[]{0x43, 0x21}
                )
        );

        assertThat(requestA).isEqualTo(requestB);
        assertThat(requestA).hasSameHashCodeAs(requestB);
    }
}
