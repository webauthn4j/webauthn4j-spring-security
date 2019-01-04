package net.sharplab.springframework.security.fido.server.endpoint;

import java.io.Serializable;

public interface ServerResponse extends Serializable {

    Status getStatus();

    String getErrorMessage();

}
