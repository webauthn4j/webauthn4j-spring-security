package net.sharplab.springframework.security.webauthn.endpoint;

import com.webauthn4j.registry.Registry;
import net.sharplab.springframework.security.webauthn.endpoint.OptionsEndpointFilter;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class OptionsEndpointFilterTest {

    private Registry registry = new Registry();

    @Test
    public void getter_setter_test() {
        OptionsEndpointFilter optionsEndpointFilter = new OptionsEndpointFilter(null, registry);
        MFATokenEvaluator mfaTokenEvaluator = new MFATokenEvaluatorImpl();
        AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
        optionsEndpointFilter.setMFATokenEvaluator(mfaTokenEvaluator);
        optionsEndpointFilter.setTrustResolver(trustResolver);
        assertThat(optionsEndpointFilter.getMFATokenEvaluator()).isEqualTo(mfaTokenEvaluator);
        assertThat(optionsEndpointFilter.getTrustResolver()).isEqualTo(trustResolver);
    }

    @Test
    public void writeErrorResponse_with_RuntimeException_test() throws IOException {
        OptionsEndpointFilter optionsEndpointFilter = new OptionsEndpointFilter(null, registry);

        MockHttpServletResponse response = new MockHttpServletResponse();
        RuntimeException exception = new RuntimeException();
        optionsEndpointFilter.writeErrorResponse(response, exception);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        assertThat(response.getContentType()).isEqualTo("application/json");
        assertThat(response.getContentAsString()).isEqualTo("{\"status\":\"failed\",\"errorMessage\":\"The server encountered an internal error\"}");
    }

    @Test
    public void writeErrorResponse_with_InsufficientAuthenticationException_test() throws IOException {
        OptionsEndpointFilter optionsEndpointFilter = new OptionsEndpointFilter(null, registry);

        MockHttpServletResponse response = new MockHttpServletResponse();
        InsufficientAuthenticationException exception = new InsufficientAuthenticationException("not privileged");
        optionsEndpointFilter.writeErrorResponse(response, exception);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getContentType()).isEqualTo("application/json");
        assertThat(response.getContentAsString()).isEqualTo("{\"status\":\"failed\",\"errorMessage\":\"Anonymous access is prohibited\"}");
    }
}
