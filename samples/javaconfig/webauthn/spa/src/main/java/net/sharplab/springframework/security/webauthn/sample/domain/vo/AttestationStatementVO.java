package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.io.Serializable;

/**
 * AttestationStatementVO
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "format")
@JsonSubTypes({
        @JsonSubTypes.Type(name = FIDOU2FAttestationStatementVO.FORMAT, value = FIDOU2FAttestationStatementVO.class),
        @JsonSubTypes.Type(name = PackedAttestationStatementVO.FORMAT, value = PackedAttestationStatementVO.class),
        @JsonSubTypes.Type(name = AndroidKeyAttestationStatementVO.FORMAT, value = AndroidKeyAttestationStatementVO.class),
        @JsonSubTypes.Type(name = AndroidSafetyNetAttestationStatementVO.FORMAT, value = AndroidSafetyNetAttestationStatementVO.class),
        @JsonSubTypes.Type(name = NoneAttestationStatementVO.FORMAT, value = NoneAttestationStatementVO.class)
})
public interface AttestationStatementVO extends Serializable {

    @JsonIgnore
    String getFormat();
}
