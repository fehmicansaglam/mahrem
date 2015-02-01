package utils;

import play.exceptions.UnexpectedException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

public final class Hmac {

    private final Mac mac;

    private Hmac(Mac mac, byte[] key) {
        this.mac = mac;
        SecretKeySpec signingKey = new SecretKeySpec(key, "HmacSHA1");
        try {
            this.mac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new UnexpectedException(e);
        }
    }

    public static Hmac init(byte[] key) {
        try {
            return new Hmac(Mac.getInstance("HmacSHA1"), key);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Hmac update(byte[] bytes, int offset, int len) {
        mac.update(bytes, offset, len);
        return this;
    }

    public byte[] result() {
        byte[] result = mac.doFinal();
        return result;
    }
}
