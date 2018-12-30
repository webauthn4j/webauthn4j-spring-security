package net.sharplab.springframework.security.webauthn.endpoint;

import java.io.Serializable;

public interface ServerResponse extends Serializable {

    Status getStatus();

    String getErrorMessage();

}
