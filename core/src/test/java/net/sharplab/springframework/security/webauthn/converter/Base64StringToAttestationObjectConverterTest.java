package net.sharplab.springframework.security.webauthn.converter;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class Base64StringToAttestationObjectConverterTest {

    @Test
    public void convert_test() {
        AttestationObject expected = TestUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        String source = new AttestationObjectConverter().convertToString(expected);
        Base64StringToAttestationObjectConverter converter = new Base64StringToAttestationObjectConverter();
        AttestationObject result = converter.convert(source);
        assertThat(result).isEqualTo(expected);
    }
}
