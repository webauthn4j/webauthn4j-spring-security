package net.sharplab.springframework.security.webauthn.options;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ErrorTest {

    @Test
    public void type_create_test() {
        assertThat(Error.Type.create("not_authenticated")).isEqualTo(Error.Type.NOT_AUTHENTICATED);
        assertThat(Error.Type.create("server_error")).isEqualTo(Error.Type.SERVER_ERROR);
        assertThatThrownBy(() -> Error.Type.create("invalid")).isInstanceOf(IllegalArgumentException.class);
    }
}
