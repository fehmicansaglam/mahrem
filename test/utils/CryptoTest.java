package utils;

import org.junit.Test;
import play.Logger;
import play.test.UnitTest;

public class CryptoTest extends UnitTest {

    final String password = "abuzer";
    final String salt = "12345678";

    @Test
    public void encrypt() throws Exception {
        final String hmac = CryptoUtils.encrypt(password, salt, "/Users/fehmicansaglam/Downloads/jdk-8u25-macosx-x64.dmg");
        Logger.info("hmac: %s", hmac);
    }

    @Test
    public void decrypt() throws Exception {
        final String hmac = CryptoUtils.decrypt(password, salt, "/Users/fehmicansaglam/Downloads/jdk-8u25-macosx-x64.dmg.enc");
        Logger.info("hmac: %s", hmac);
    }

}
