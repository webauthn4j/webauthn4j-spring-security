package net.sharplab.springframework.security.webauthn.util;

import com.webauthn4j.client.Origin;

import javax.servlet.http.HttpServletRequest;

public class ServletUtil {

    public static Origin getOrigin(HttpServletRequest request) {
        return new Origin(request.getScheme(), request.getServerName(), request.getServerPort());
    }
}
