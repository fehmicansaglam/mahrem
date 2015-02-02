package controllers;

import models.EncryptedFile;
import play.Logger;
import play.libs.Codec;
import play.libs.MimeTypes;
import play.mvc.Controller;
import utils.CryptoUtils;
import utils.KeyTuple;

import java.io.File;
import java.util.List;

public class Application extends Controller {

    public static void index() {
        List<EncryptedFile> files = EncryptedFile.findAll();
        render(files);
    }

    public static void save(String password, File file) throws Exception {
        final String salt = CryptoUtils.salt();
        final KeyTuple keyTuple = CryptoUtils.deriveKey(password, salt, 256);
        Logger.info("key1: %s", Codec.byteToHexString(keyTuple.left));
        Logger.info("key2: %s", Codec.byteToHexString(keyTuple.right));

        final String hash = CryptoUtils.sha1(keyTuple.key);
        final String uuid = Codec.UUID();
        final String hmac = CryptoUtils.encrypt(keyTuple, file, "public/uploads/" + uuid);
        new EncryptedFile(file.getName(), uuid, file.length(), salt, hash, hmac).save();
        index();
    }

    public static void get(String uuid) {
        notFoundIfNull(uuid);
        render();
    }

    public static void decrypt(String uuid, String password) throws Exception {
        EncryptedFile encryptedFile = EncryptedFile.find("uuid", uuid).first();
        notFoundIfNull(encryptedFile);

        final KeyTuple keyTuple = CryptoUtils.deriveKey(password, encryptedFile.salt, 256);
        Logger.info("key1: %s", Codec.byteToHexString(keyTuple.left));
        Logger.info("key2: %s", Codec.byteToHexString(keyTuple.right));

        if (!encryptedFile.hash.equals(CryptoUtils.sha1(keyTuple.key))) {
            forbidden();
        }

        response.setContentTypeIfNotSet(MimeTypes.getContentType(encryptedFile.name));
        final String hmac = CryptoUtils.decrypt(keyTuple, "public/uploads/" + uuid, response.out);
        if (!hmac.equals(encryptedFile.hmac)) {
            error("hmac");
        }
    }

}