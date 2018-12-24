package net.sharplab.springframework.security.webauthn.anchor;

import com.webauthn4j.anchor.KeyStoreException;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.security.cert.TrustAnchor;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class KeyStoreResourceTrustAnchorProviderTest {

    private KeyStoreResourceTrustAnchorProvider target;

    @Test
    public void provide_test() {
        target = new KeyStoreResourceTrustAnchorProvider();
        Resource resource = new ClassPathResource("net/sharplab/springframework/security/webauthn/anchor/KeyStoreResourceTrustAnchorProviderImplTest/test.jks");
        target.setKeyStore(resource);
        target.setPassword("password");

        Set<TrustAnchor> trustAnchors = target.provide();
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test(expected = KeyStoreException.class)
    public void provide_test_with_invalid_path() {
        target = new KeyStoreResourceTrustAnchorProvider();
        Resource resource = new ClassPathResource("invalid.path.to.jks");
        target.setKeyStore(resource);
        target.setPassword("password");

        target.provide();
    }

    @Test(expected = IllegalArgumentException.class)
    public void afterPropertiesSet_test(){
        KeyStoreResourceTrustAnchorProvider trustAnchorProvider = new KeyStoreResourceTrustAnchorProvider();
        trustAnchorProvider.afterPropertiesSet();
    }
}
