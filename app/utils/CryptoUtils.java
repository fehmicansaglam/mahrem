package utils;

import org.apache.commons.lang.RandomStringUtils;
import play.Logger;
import play.exceptions.UnexpectedException;
import play.libs.Codec;
import play.libs.Crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;

public abstract class CryptoUtils {

    public static String salt() {
        return RandomStringUtils.randomAlphanumeric(8);
    }

    public static KeyTuple deriveKey(final String password,
                                     final String salt,
                                     final int length) {
        try {
            final SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            final KeySpec ks = new PBEKeySpec(password.toCharArray(), salt.getBytes("utf-8"), 1000, length);
            final SecretKey s = f.generateSecret(ks);
            return new KeyTuple(s.getEncoded());
        } catch (Exception e) {
            Logger.error(e, "");
            throw new UnexpectedException(e);
        }
    }

    /**
     * Returns base-64 representation
     */
    public static String sha1(final byte[] bytes) {
        try {
            MessageDigest m = MessageDigest.getInstance(Crypto.HashType.SHA1.toString());
            byte[] out = m.digest(bytes);
            return Codec.byteToHexString(out);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String encrypt(final KeyTuple keyTuple,
                                 final File infile,
                                 final String outfile) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(keyTuple.left, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(new byte[16]));

        byte buffer[] = new byte[4096];
        Hmac hmac = Hmac.init(keyTuple.right);
        try (InputStream is = new FileInputStream(infile);
             OutputStream os = new FileOutputStream(outfile)) {
            int len;

            while ((len = is.read(buffer)) > 0) {
                byte[] result = cipher.update(buffer, 0, len);
                hmac.update(buffer, 0, len);
                os.write(result);
            }

            byte[] result = cipher.doFinal();
            os.write(result);
        }
        return Codec.byteToHexString(hmac.result());
    }

    public static String decrypt(final KeyTuple keyTuple,
                                 final String infile,
                                 final OutputStream os) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(keyTuple.left, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5padding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(new byte[16]));

        byte buffer[] = new byte[4096];
        Hmac hmac = Hmac.init(keyTuple.right);
        try (InputStream is = new FileInputStream(infile)) {
            int len;

            while ((len = is.read(buffer)) > 0) {
                byte[] result = cipher.update(buffer, 0, len);
                hmac.update(result, 0, result.length);
                os.write(result);
            }

            byte[] result = cipher.doFinal();
            hmac.update(result, 0, result.length);
            os.write(result);
        }
        return Codec.byteToHexString(hmac.result());
    }

}
