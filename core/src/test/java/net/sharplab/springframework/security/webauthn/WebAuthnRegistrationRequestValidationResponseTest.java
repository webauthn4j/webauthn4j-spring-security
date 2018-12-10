package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.client.ClientDataType;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.extension.client.ClientExtensionOutput;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnRegistrationRequestValidationResponseTest {

    @Test
    public void equals_hashCode_test() {
        CollectedClientData clientData = TestUtil.createClientData(ClientDataType.CREATE);
        AttestationObject attestationObject = TestUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        Map<String, ClientExtensionOutput> clientExtensions = new HashMap<>();
        WebAuthnRegistrationRequestValidationResponse instanceA =
                new WebAuthnRegistrationRequestValidationResponse(clientData, attestationObject, clientExtensions);
        WebAuthnRegistrationRequestValidationResponse instanceB =
                new WebAuthnRegistrationRequestValidationResponse(clientData, attestationObject, clientExtensions);
        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceB).hasSameHashCodeAs(instanceB);
    }

    @Test
    public void getter_test(){
        CollectedClientData clientData = TestUtil.createClientData(ClientDataType.CREATE);
        AttestationObject attestationObject = TestUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        Map<String, ClientExtensionOutput> clientExtensions = new HashMap<>();
        WebAuthnRegistrationRequestValidationResponse instance =
                new WebAuthnRegistrationRequestValidationResponse(clientData, attestationObject, clientExtensions);

        assertThat(instance.getCollectedClientData()).isEqualTo(clientData);
        assertThat(instance.getAttestationObject()).isEqualTo(attestationObject);
        assertThat(instance.getClientExtensionOutputs()).isEqualTo(clientExtensions);
    }
}
