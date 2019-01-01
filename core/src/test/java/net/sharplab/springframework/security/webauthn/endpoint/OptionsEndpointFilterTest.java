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


}
