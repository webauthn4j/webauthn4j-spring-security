package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import com.webauthn4j.attestation.authenticator.Curve;
import com.webauthn4j.attestation.statement.COSEKeyType;

import java.util.Arrays;
import java.util.Objects;

public class EC2CredentialPublicKeyVO extends AbstractCredentialPublicKeyVO {

    private Curve curve;
    private byte[] x;
    private byte[] y;

    @Override
    public COSEKeyType getKeyType() {
        return COSEKeyType.EC2;
    }

    public Curve getCurve() {
        return curve;
    }

    public void setCurve(Curve curve) {
        this.curve = curve;
    }

    public byte[] getX() {
        return x;
    }

    public void setX(byte[] x) {
        this.x = x;
    }

    public byte[] getY() {
        return y;
    }

    public void setY(byte[] y) {
        this.y = y;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EC2CredentialPublicKeyVO that = (EC2CredentialPublicKeyVO) o;
        return curve == that.curve &&
                Arrays.equals(x, that.x) &&
                Arrays.equals(y, that.y);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(super.hashCode(), curve);
        result = 31 * result + Arrays.hashCode(x);
        result = 31 * result + Arrays.hashCode(y);
        return result;
    }
}
