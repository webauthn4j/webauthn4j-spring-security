package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import java.util.Arrays;

public class RSCredentialPublicKeyVO extends AbstractCredentialPublicKeyVO {

    private byte[] n;
    private byte[] e;

    public byte[] getN() {
        return n;
    }

    public void setN(byte[] n) {
        this.n = n;
    }

    public byte[] getE() {
        return e;
    }

    public void setE(byte[] e) {
        this.e = e;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RSCredentialPublicKeyVO that = (RSCredentialPublicKeyVO) o;
        return Arrays.equals(n, that.n) &&
                Arrays.equals(e, that.e);
    }

    @Override
    public int hashCode() {

        int result = Arrays.hashCode(n);
        result = 31 * result + Arrays.hashCode(e);
        return result;
    }
}
