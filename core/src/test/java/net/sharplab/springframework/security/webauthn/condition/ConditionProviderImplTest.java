package net.sharplab.springframework.security.webauthn.condition;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class ConditionProviderImplTest {

    @Test
    public void provide_test() {
        String challenge = Base64UrlUtil.encodeToString(TestUtil.createChallenge().getValue());
        byte[] credentialId = new byte[]{0x01, 0x23, 0x45};
        WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);
        WebAuthnUserDetails userDetails = mock(WebAuthnUserDetails.class);
        Authenticator authenticator = mock(Authenticator.class, RETURNS_DEEP_STUBS);
        List<Authenticator> authenticators = Collections.singletonList(authenticator);

        when(userDetailsService.loadUserByUsername(any())).thenReturn(userDetails);
        doReturn(authenticators).when(userDetails).getAuthenticators();
        when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);

        ConditionProvider conditionProvider = new ConditionProviderImpl(userDetailsService);
        ServerProperty serverProperty = new ServerProperty(
                new Origin("https://example.com"),
                "example.com",
                new DefaultChallenge(challenge),
                new byte[32]
        );

        Condition condition = conditionProvider.provide("dummy", serverProperty);
        assertThat(condition.getRpId()).isEqualTo("example.com");
        assertThat(condition.getChallenge()).isEqualTo(challenge);
        assertThat(condition.getCredentials()).extracting("id").containsExactly(Base64UrlUtil.encodeToString(credentialId));

    }


}
