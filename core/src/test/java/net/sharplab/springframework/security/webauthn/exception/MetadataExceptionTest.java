package net.sharplab.springframework.security.webauthn.exception;

import org.junit.Test;

public class MetadataExceptionTest {
    private RuntimeException cause = new RuntimeException();

    @Test
    public void test() {
        new MetadataException("dummy", cause);
        new MetadataException("dummy");
        new MetadataException(cause);
    }
}
