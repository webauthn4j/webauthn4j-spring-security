package net.sharplab.springframework.security.webauthn.sample.util.modelmapper;

import com.webauthn4j.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import net.sharplab.springframework.security.webauthn.sample.domain.config.ModelMapperConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.PackedAttestationStatementVO;
import org.junit.Test;
import org.modelmapper.ModelMapper;

import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class AttestationStatementToAttestationStatementVOConverterTest {

    @Test
    public void test(){
        ModelMapper modelMapper = ModelMapperConfig.createModelMapper();

        byte[] sig = new byte[32];
        byte[] ecdaaKeyId = new byte[64];
        X509Certificate certificate = mock(X509Certificate.class);
        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath(Collections.singletonList(certificate));
        PackedAttestationStatement packedAttestationStatement =
                new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, sig, attestationCertificatePath, ecdaaKeyId);
        PackedAttestationStatementVO result = modelMapper.map(packedAttestationStatement, PackedAttestationStatementVO.class);

        assertThat(result.getAlg()).isEqualTo(COSEAlgorithmIdentifier.ES256);
        assertThat(result.getSig()).isEqualTo(sig);
        assertThat(result.getX5c()).isEqualTo(attestationCertificatePath);
        assertThat(result.getEcdaaKeyId()).isEqualTo(ecdaaKeyId);
    }
}
