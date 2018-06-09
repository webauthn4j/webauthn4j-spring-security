package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import com.webauthn4j.attestation.authenticator.Curve;

import java.util.Arrays;
import java.util.Objects;

public class ECCredentialPublicKeyVO extends AbstractCredentialPublicKeyVO {

    private Curve curve;
    private byte[] x;
    private byte[] y;
    private byte[] d;

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

    public byte[] getD() {
        return d;
    }

    public void setD(byte[] d) {
        this.d = d;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ECCredentialPublicKeyVO that = (ECCredentialPublicKeyVO) o;
        return curve == that.curve &&
                Arrays.equals(x, that.x) &&
                Arrays.equals(y, that.y) &&
                Arrays.equals(d, that.d);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(super.hashCode(), curve);
        result = 31 * result + Arrays.hashCode(x);
        result = 31 * result + Arrays.hashCode(y);
        result = 31 * result + Arrays.hashCode(d);
        return result;
    }
}
