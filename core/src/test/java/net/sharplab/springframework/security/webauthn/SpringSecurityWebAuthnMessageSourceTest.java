package net.sharplab.springframework.security.webauthn;

import org.junit.Test;
import org.springframework.context.support.MessageSourceAccessor;

import static org.assertj.core.api.Assertions.assertThat;

public class SpringSecurityWebAuthnMessageSourceTest {

    @Test
    public void getAccessor_test(){
        MessageSourceAccessor accessor = SpringSecurityWebAuthnMessageSource.getAccessor();
        String credentialIdStr = "dummyCredentialId";
        String message = accessor.getMessage("JdbcWebAuthnAuthenticatorServiceImpl.notFound", new Object[]{credentialIdStr});
        assertThat(message).isEqualTo("Authenticator dummyCredentialId not found");
    }
}
