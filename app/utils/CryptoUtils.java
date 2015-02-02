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
import java.security.spec.KeySpec;
import java.util.Arrays;

public abstract class CryptoUtils {

    public static String salt() {
        return RandomStringUtils.randomAlphanumeric(8);
    }

    public static byte[] deriveKey(final String password,
                                   final String salt,
                                   final int length) {
        try {
            final SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            final KeySpec ks = new PBEKeySpec(password.toCharArray(), salt.getBytes("utf-8"), 1000, length);
            final SecretKey s = f.generateSecret(ks);
            return s.getEncoded();
        } catch (Exception e) {
            Logger.error(e, "");
            throw new UnexpectedException(e);
        }
    }

    /**
     * Returns base-64 representation
     */
    public static String sha1(final String password, final String salt) {
        return Crypto.passwordHash(salt + password, Crypto.HashType.SHA1);
    }

    public static String encrypt(final String password,
                                 final String salt,
                                 final File infile,
                                 final String outfile) throws Exception {
        final byte[] key = CryptoUtils.deriveKey(password, salt, 256);
        final byte[] key1 = Arrays.copyOfRange(key, 0, key.length / 2);
        final byte[] key2 = Arrays.copyOfRange(key, key.length / 2, key.length);
        Logger.info("key1: %s", Codec.byteToHexString(key1));
        Logger.info("key2: %s", Codec.byteToHexString(key2));

        SecretKeySpec skeySpec = new SecretKeySpec(key1, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(new byte[16]));

        byte buffer[] = new byte[4096];
        Hmac hmac = Hmac.init(key2);
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

    public static String decrypt(final String password,
                                 final String salt,
                                 final String infile,
                                 final OutputStream os) throws Exception {
        final byte[] key = CryptoUtils.deriveKey(password, salt, 256);
        final byte[] key1 = Arrays.copyOfRange(key, 0, key.length / 2);
        final byte[] key2 = Arrays.copyOfRange(key, key.length / 2, key.length);
        Logger.info("key1: %s", Codec.byteToHexString(key1));
        Logger.info("key2: %s", Codec.byteToHexString(key2));

        SecretKeySpec skeySpec = new SecretKeySpec(key1, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5padding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(new byte[16]));

        byte buffer[] = new byte[4096];
        Hmac hmac = Hmac.init(key2);
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
