package integration.scenario;

import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.authenticator.fido.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.test.client.*;
import net.sharplab.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Collections;

public class FIDOU2FAuthenticatorTest {

    private Origin origin = new Origin("http://example.com");
    private ClientPlatform clientPlatform = new ClientPlatform(origin, new FIDOU2FAuthenticatorAdaptor());

    @Ignore
    @Test
    public void test() {
        Challenge challenge = new DefaultChallenge();

        // create
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        PublicKeyCredential<AuthenticatorAttestationResponse> createResult = clientPlatform.create(credentialCreationOptions);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0,
                "example.com",
                Collections.emptyList(),
                UserVerificationRequirement.PREFERRED,
                Collections.emptyMap()
        );
        PublicKeyCredential<AuthenticatorAssertionResponse> getResult = clientPlatform.get(credentialRequestOptions);
        ServerProperty serverProperty = new ServerProperty(
                new Origin("https://example.com"),
                "example.com",
                challenge,
                new byte[0]
        );

        WebAuthnAuthenticationRequest authenticationRequest = new WebAuthnAuthenticationRequest(
                getResult.getRawId(),
                getResult.getAuthenticatorResponse().getClientDataJSON(),
                getResult.getAuthenticatorResponse().getAuthenticatorData(),
                getResult.getAuthenticatorResponse().getSignature(),
                "", //TODO
                serverProperty
        );

    }
}
