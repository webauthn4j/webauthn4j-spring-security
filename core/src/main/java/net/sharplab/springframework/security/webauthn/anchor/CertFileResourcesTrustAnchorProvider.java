package net.sharplab.springframework.security.webauthn.anchor;

import com.webauthn4j.anchor.CachingTrustAnchorProviderBase;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CertificateUtil;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CertFileResourcesTrustAnchorProvider extends CachingTrustAnchorProviderBase implements InitializingBean {

    private List<Resource> pemFiles;

    public CertFileResourcesTrustAnchorProvider(){
    }

    public CertFileResourcesTrustAnchorProvider(List<Resource> pemFiles) {
        this.pemFiles = pemFiles;
    }

    @Override
    public void afterPropertiesSet() {
        checkConfig();
    }

    private void checkConfig(){
        AssertUtil.notNull(pemFiles, "pemFile must not be null");
    }

    @Override
    protected Set<TrustAnchor> loadTrustAnchors() {
        return pemFiles.stream().map(this::loadTrustAnchor).collect(Collectors.toSet());
    }

    public List<Resource> getPemFiles() {
        return pemFiles;
    }

    public void setPemFiles(List<Resource> pemFiles) {
        this.pemFiles = pemFiles;
    }

    private TrustAnchor loadTrustAnchor(Resource pemFile){
        checkConfig();
        try {
            X509Certificate certificate = CertificateUtil.generateX509Certificate(pemFile.getInputStream());
            return new TrustAnchor(certificate, null);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
