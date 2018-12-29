package net.sharplab.springframework.security.webauthn.converter;

import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.client.ClientDataType;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class Base64StringToCollectedClientDataConverterTest {

    private Registry registry = new Registry();

    @Test
    public void convert_test() {
        CollectedClientData expected = TestUtil.createClientData(ClientDataType.GET);
        String source = new CollectedClientDataConverter(registry).convertToBase64UrlString(expected);

        CollectedClientData result = new Base64StringToCollectedClientDataConverter(registry).convert(source);

        assertThat(result).isEqualTo(expected);
    }
}
