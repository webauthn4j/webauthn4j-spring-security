package net.sharplab.springframework.security.webauthn;

import org.junit.Test;
import org.springframework.context.support.MessageSourceAccessor;

import static org.assertj.core.api.Assertions.assertThat;

public class SpringSecurityWebAuthnMessageSourceTest {

    @Test
    public void getAccessor_test(){
        MessageSourceAccessor accessor = SpringSecurityWebAuthnMessageSource.getAccessor();
        assertThat(accessor).isNotNull();
    }
}
