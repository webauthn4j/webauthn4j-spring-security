package net.sharplab.springframework.security.webauthn.authenticator;

import com.webauthn4j.attestation.authenticator.Curve;
import com.webauthn4j.attestation.authenticator.ECCredentialPublicKey;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.attestation.statement.COSEKeyType;
import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.junit4.SpringRunner;

import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;

@JdbcTest
@RunWith(SpringRunner.class)
public class TestJdbcWebAuthnAuthenticatorServiceImplTest {

    @Autowired
    private JdbcWebAuthnAuthenticatorServiceImpl jdbcWebAuthnAuthenticatorService;

    @Test
    @Sql({"classpath:/db/h2/ddl.sql", "classpath:/db/h2/fixture.sql"})
    public void test(){
        byte[] credentialId = Base64UrlUtil.decode("s8AQDFKjRQq2NYgW0nqWmg");
        WebAuthnAuthenticator authenticator = jdbcWebAuthnAuthenticatorService.loadWebAuthnAuthenticatorByCredentialId(credentialId);
        assertThat(authenticator.getName()).isEqualTo("test authenticator");
        assertThat(authenticator.getCounter()).isZero();
        assertThat(authenticator.getAttestationStatement().getFormat()).isEqualTo(NoneAttestationStatement.FORMAT);
        assertThat(authenticator.getAttestedCredentialData().getAaGuid()).isEmpty();
        assertThat(authenticator.getAttestedCredentialData().getCredentialId()).isEqualTo(credentialId);
        assertThat(authenticator.getAttestedCredentialData().getCredentialPublicKey()).isInstanceOf(ECCredentialPublicKey.class);

        ECCredentialPublicKey publicKey = (ECCredentialPublicKey) authenticator.getAttestedCredentialData().getCredentialPublicKey();
        assertThat(publicKey.getKeyType()).isEqualTo(COSEKeyType.EC2);
        assertThat(publicKey.getCurve()).isEqualTo(Curve.SECP256R1);
        assertThat(publicKey.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.ES256);
        assertThat(publicKey.getX()).isEqualTo(Base64UrlUtil.decode("Iu73zyeHdP6PDgD8f8srbZSibRpeCrd-skMOQ0FU6qw"));
        assertThat(publicKey.getY()).isEqualTo(Base64UrlUtil.decode("cwNZ5OE6-BOmJu7s3a7AVI8uHJu3dLWiXS8di87zNu8"));
    }


    @Configuration
    static class Config {

        @Bean
        public JdbcWebAuthnAuthenticatorServiceImpl jdbcWebAuthnAuthenticatorService(DataSource datasource){
            JdbcWebAuthnAuthenticatorServiceImpl instance = new JdbcWebAuthnAuthenticatorServiceImpl();
            instance.setDataSource(datasource);
            return instance;
        }

    }
}
