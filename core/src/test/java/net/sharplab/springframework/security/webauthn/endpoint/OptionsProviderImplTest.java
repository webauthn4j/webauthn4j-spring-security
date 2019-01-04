package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.request.PublicKeyCredentialParameters;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.assertj.core.util.Lists;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class OptionsProviderImplTest {

    @Test
    public void getAttestationOptions_test() {
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[]{0x01, 0x23, 0x45};
        WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);
        WebAuthnUserDetails userDetails = mock(WebAuthnUserDetails.class);
        Authenticator authenticator = mock(Authenticator.class, RETURNS_DEEP_STUBS);
        List<Authenticator> authenticators = Collections.singletonList(authenticator);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);

        MockHttpServletRequest mockRequest = new MockHttpServletRequest();

        when(userDetailsService.loadUserByUsername(any())).thenReturn(userDetails);
        doReturn(new byte[0]).when(userDetails).getUserHandle();
        doReturn(authenticators).when(userDetails).getAuthenticators();
        when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);
        when(challengeRepository.loadOrGenerateChallenge(mockRequest)).thenReturn(challenge);

        OptionsProvider optionsProvider = new OptionsProviderImpl(userDetailsService, challengeRepository);
        optionsProvider.setRpId("example.com");
        optionsProvider.setRpName("rpName");

        AttestationOptions attestationOptions = optionsProvider.getAttestationOptions(mockRequest,"dummy", null);
        assertThat(attestationOptions.getRelyingParty().getId()).isEqualTo("example.com");
        assertThat(attestationOptions.getRelyingParty().getName()).isEqualTo("rpName");
        assertThat(attestationOptions.getChallenge()).isEqualTo(challenge);
        assertThat(attestationOptions.getCredentials()).containsExactly(Base64UrlUtil.encodeToString(credentialId));

    }

    @Test
    public void getter_setter_test(){
        WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);
        ChallengeRepository challengeRepository = mock(ChallengeRepository.class);
        OptionsProviderImpl optionsProvider = new OptionsProviderImpl(userDetailsService, challengeRepository);

        optionsProvider.setRpId("example.com");
        assertThat(optionsProvider.getRpId()).isEqualTo("example.com");
        optionsProvider.setRpName("example");
        assertThat(optionsProvider.getRpName()).isEqualTo("example");
        List<PublicKeyCredentialParameters> publicKeyCredParams = Lists.emptyList();
        optionsProvider.setPubKeyCredParams(publicKeyCredParams);
        assertThat(optionsProvider.getPubKeyCredParams()).isEqualTo(publicKeyCredParams);
        optionsProvider.setRegistrationTimeout(BigInteger.valueOf(10000));
        assertThat(optionsProvider.getRegistrationTimeout()).isEqualTo(BigInteger.valueOf(10000));

        optionsProvider.setUsernameParameter("usernameParameter");
        assertThat(optionsProvider.getUsernameParameter()).isEqualTo("usernameParameter");
        optionsProvider.setPasswordParameter("passwordParameter");
        assertThat(optionsProvider.getPasswordParameter()).isEqualTo("passwordParameter");
        optionsProvider.setCredentialIdParameter("credentialIdParameter");
        assertThat(optionsProvider.getCredentialIdParameter()).isEqualTo("credentialIdParameter");
        optionsProvider.setClientDataJSONParameter("clientDataParameter");
        assertThat(optionsProvider.getClientDataJSONParameter()).isEqualTo("clientDataParameter");
        optionsProvider.setAuthenticatorDataParameter("authenticatorDataParameter");
        assertThat(optionsProvider.getAuthenticatorDataParameter()).isEqualTo("authenticatorDataParameter");
        optionsProvider.setSignatureParameter("signatureParameter");
        assertThat(optionsProvider.getSignatureParameter()).isEqualTo("signatureParameter");
        optionsProvider.setClientExtensionsJSONParameter("clientExtensionsJSONParameter");
        assertThat(optionsProvider.getClientExtensionsJSONParameter()).isEqualTo("clientExtensionsJSONParameter");

    }

}
