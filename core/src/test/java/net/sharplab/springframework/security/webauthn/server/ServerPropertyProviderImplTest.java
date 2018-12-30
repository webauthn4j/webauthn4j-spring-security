package net.sharplab.springframework.security.webauthn.server;

import com.webauthn4j.response.client.Origin;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.endpoint.OptionsProvider;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ServerPropertyProviderImplTest {

    private ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
    private OptionsProvider optionsProvider = mock(OptionsProvider.class);
    private ServerPropertyProviderImpl target = new ServerPropertyProviderImpl(optionsProvider, challengeRepository);

    @Test
    public void provide_test() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("origin.example.com");
        request.setServerPort(443);
        Challenge mockChallenge = new DefaultChallenge();
        when(challengeRepository.loadOrGenerateChallenge(request)).thenReturn(mockChallenge);
        when(optionsProvider.getEffectiveRpId(request)).thenReturn("rpid.example.com");

        ServerProperty serverProperty = target.provide(request);

        assertThat(serverProperty.getRpId()).isEqualTo("rpid.example.com");
        assertThat(serverProperty.getOrigin()).isEqualTo(new Origin("https://origin.example.com"));
        assertThat(serverProperty.getChallenge()).isEqualTo(mockChallenge);
    }
}
