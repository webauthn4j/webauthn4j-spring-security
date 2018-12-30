package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.response.attestation.AttestationObject;
import com.webauthn4j.response.client.ClientDataType;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.response.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnRegistrationRequestValidationResponseTest {

    @Test
    public void equals_hashCode_test() {
        CollectedClientData clientData = TestUtil.createClientData(ClientDataType.CREATE);
        AttestationObject attestationObject = TestUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        AuthenticationExtensionsClientOutputs clientExtensions = new AuthenticationExtensionsClientOutputs();
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
        AuthenticationExtensionsClientOutputs clientExtensions = new AuthenticationExtensionsClientOutputs();
        WebAuthnRegistrationRequestValidationResponse instance =
                new WebAuthnRegistrationRequestValidationResponse(clientData, attestationObject, clientExtensions);

        assertThat(instance.getCollectedClientData()).isEqualTo(clientData);
        assertThat(instance.getAttestationObject()).isEqualTo(attestationObject);
        assertThat(instance.getRegistrationExtensionsClientOutputs()).isEqualTo(clientExtensions);
    }
}
