package net.sharplab.springframework.security.webauthn.anchor;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class CertFileResourcesTrustAnchorProviderTest {


    @Test
    public void load_pemFile_test() {
        CertFileResourcesTrustAnchorProvider trustAnchorProvider = new CertFileResourcesTrustAnchorProvider();
        Resource resource = new ClassPathResource("certs/3tier-test-root-CA.pem");
        trustAnchorProvider.setPemFiles(Collections.singletonList(resource));
        Set<TrustAnchor> trustAnchors = trustAnchorProvider.loadTrustAnchors();
        assertThat(trustAnchors).hasSize(1);
    }

    @Test
    public void load_derFile_test() {
        CertFileResourcesTrustAnchorProvider trustAnchorProvider = new CertFileResourcesTrustAnchorProvider();
        Resource resource = new ClassPathResource("certs/3tier-test-root-CA.der");
        trustAnchorProvider.setPemFiles(Collections.singletonList(resource));
        Set<TrustAnchor> trustAnchors = trustAnchorProvider.loadTrustAnchors();
        assertThat(trustAnchors).hasSize(1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void afterPropertiesSet_test() {
        CertFileResourcesTrustAnchorProvider trustAnchorProvider = new CertFileResourcesTrustAnchorProvider();
        trustAnchorProvider.afterPropertiesSet();
    }
}
