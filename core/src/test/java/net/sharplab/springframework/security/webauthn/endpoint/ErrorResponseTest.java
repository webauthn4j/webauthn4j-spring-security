package net.sharplab.springframework.security.webauthn.endpoint;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ErrorResponseTest {

    @Test
    public void type_create_test() {
        assertThat(Status.create("ok")).isEqualTo(Status.OK);
        assertThat(Status.create("failed")).isEqualTo(Status.FAILED);
        assertThatThrownBy(() -> Status.create("invalid")).isInstanceOf(IllegalArgumentException.class);
    }
}
