package net.sharplab.springframework.security.webauthn.condition;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class ConditionEndpointFilterTest {

    @Test
    public void getter_setter_test(){
        ConditionEndpointFilter conditionEndpointFilter = new ConditionEndpointFilter(null, null);
        MFATokenEvaluator mfaTokenEvaluator = new MFATokenEvaluatorImpl();
        AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
        conditionEndpointFilter.setMFATokenEvaluator(mfaTokenEvaluator);
        conditionEndpointFilter.setTrustResolver(trustResolver);
        assertThat(conditionEndpointFilter.getMfaTokenEvaluator()).isEqualTo(mfaTokenEvaluator);
        assertThat(conditionEndpointFilter.getTrustResolver()).isEqualTo(trustResolver);
    }

    @Test
    public void writeErrorResponse_with_RuntimeException_test() throws IOException {
        ConditionEndpointFilter conditionEndpointFilter = new ConditionEndpointFilter(null, null);

        MockHttpServletResponse response = new MockHttpServletResponse();
        RuntimeException exception = new RuntimeException();
        conditionEndpointFilter.writeErrorResponse(response, exception);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        assertThat(response.getContentType()).isEqualTo("application/json");
        assertThat(response.getContentAsString()).isEqualTo("{\"type\":\"server_error\",\"message\":\"The server encountered an internal error\"}");
    }

    @Test
    public void writeErrorResponse_with_InsufficientAuthenticationException_test() throws IOException {
        ConditionEndpointFilter conditionEndpointFilter = new ConditionEndpointFilter(null, null);

        MockHttpServletResponse response = new MockHttpServletResponse();
        InsufficientAuthenticationException exception = new InsufficientAuthenticationException("not privileged");
        conditionEndpointFilter.writeErrorResponse(response, exception);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getContentType()).isEqualTo("application/json");
        assertThat(response.getContentAsString()).isEqualTo("{\"type\":\"not_authenticated\",\"message\":\"Anonymous access is prohibited\"}");
    }
}
