//package net.sharplab.springframework.security.webauthn.authenticator;
//
//import org.junit.Test;
//import org.springframework.context.support.MessageSourceAccessor;
//
//import static org.assertj.core.api.Assertions.assertThat;
//
//public class JdbcWebAuthnAuthenticatorServiceImplTest {
//
//    private JdbcWebAuthnAuthenticatorServiceImpl target = new JdbcWebAuthnAuthenticatorServiceImpl();
//
//    @Test
//    public void getter_setter_test(){
//        MessageSourceAccessor accessor = target.getMessages();
//        String credentialIdStr = "dummyCredentialId";
//        String message = accessor.getMessage("JdbcWebAuthnAuthenticatorServiceImpl.notFound", new Object[]{credentialIdStr});
//        assertThat(message).isEqualTo("Authenticator dummyCredentialId not found");
//    }
//
//}
