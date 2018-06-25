package net.sharplab.springframework.security.webauthn.exception;

import org.junit.Test;

public class CredentialIdNotFoundExceptionTest {
    private RuntimeException cause = new RuntimeException();

    @Test
    public void test() {
        new CredentialIdNotFoundException("dummy", cause);
        new CredentialIdNotFoundException("dummy");
    }
}
