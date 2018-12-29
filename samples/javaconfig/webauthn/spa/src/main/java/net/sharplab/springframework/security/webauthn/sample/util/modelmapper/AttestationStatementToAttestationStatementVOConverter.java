package net.sharplab.springframework.security.webauthn.sample.util.modelmapper;

import com.webauthn4j.response.attestation.statement.*;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.*;
import org.modelmapper.Converter;
import org.modelmapper.spi.MappingContext;

/**
 * Converter which converts from {@link AttestationStatement} to {@link AttestationStatementVO}
 */
public class AttestationStatementToAttestationStatementVOConverter implements Converter<AttestationStatement, AttestationStatementVO> {

    @Override
    public AttestationStatementVO convert(MappingContext<AttestationStatement, AttestationStatementVO> context) {
        AttestationStatement source = context.getSource();
        AttestationStatementVO destination = context.getDestination();
        if (source == null) {
            return null;
        }
        Class sourceClass = source.getClass();
        if (sourceClass == PackedAttestationStatement.class) {
            if (destination == null) {
                destination = new PackedAttestationStatementVO();
            }
            context.getMappingEngine().map(context.create((PackedAttestationStatement) source, destination));
        }
        else if (sourceClass == FIDOU2FAttestationStatement.class) {
            if (destination == null) {
                destination = new FIDOU2FAttestationStatementVO();
            }
            context.getMappingEngine().map(context.create((FIDOU2FAttestationStatement) source, destination));
        }
        else if (sourceClass == AndroidKeyAttestationStatement.class) {
            if (destination == null) {
                destination = new AndroidKeyAttestationStatementVO();
            }
            context.getMappingEngine().map(context.create((AndroidKeyAttestationStatement) source, destination));
        }
        else if (sourceClass == AndroidSafetyNetAttestationStatement.class) {
            if (destination == null) {
                destination = new AndroidSafetyNetAttestationStatementVO();
            }
            context.getMappingEngine().map(context.create((AndroidSafetyNetAttestationStatement) source, destination));
        }
        else if (sourceClass == NoneAttestationStatement.class) {
            if (destination == null) {
                destination = new NoneAttestationStatementVO();
            }
            context.getMappingEngine().map(context.create((NoneAttestationStatement) source, destination));
        }
        else {
            throw new IllegalArgumentException();
        }
        return destination;
    }
}
