package net.sharplab.springframework.security.webauthn.options;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class OptionsProviderImplTest {

    @Test
    public void provide_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[]{0x01, 0x23, 0x45};
        WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);
        WebAuthnUserDetails userDetails = mock(WebAuthnUserDetails.class);
        Authenticator authenticator = mock(Authenticator.class, RETURNS_DEEP_STUBS);
        List<Authenticator> authenticators = Collections.singletonList(authenticator);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);

        MockHttpServletRequest mockRequest = new MockHttpServletRequest();

        when(userDetailsService.loadUserByUsername(any())).thenReturn(userDetails);
        doReturn(authenticators).when(userDetails).getAuthenticators();
        when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);
        when(challengeRepository.loadOrGenerateChallenge(mockRequest)).thenReturn(challenge);

        OptionsProvider optionsProvider = new OptionsProviderImpl(userDetailsService, challengeRepository);
        optionsProvider.setRpId("example.com");
        optionsProvider.setRpName("rpName");

        Options options = optionsProvider.provide(mockRequest,"dummy");
        assertThat(options.getRelyingParty().getId()).isEqualTo("example.com");
        assertThat(options.getRelyingParty().getName()).isEqualTo("rpName");
        assertThat(options.getChallenge()).isEqualTo(challenge);
        assertThat(options.getCredentials()).extracting("id").containsExactly(Base64UrlUtil.encodeToString(credentialId));

    }


}
