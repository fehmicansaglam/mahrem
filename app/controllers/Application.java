package controllers;

import models.EncryptedFile;
import play.libs.Codec;
import play.libs.MimeTypes;
import play.mvc.Controller;
import utils.CryptoUtils;

import java.io.File;
import java.util.List;

public class Application extends Controller {

    public static void index() {
        List<EncryptedFile> files = EncryptedFile.findAll();
        render(files);
    }

    public static void save(String password, File file) throws Exception {
        final String salt = CryptoUtils.salt();
        final String hash = CryptoUtils.sha1(password, salt);
        final String uuid = Codec.UUID();
        final String hmac = CryptoUtils.encrypt(password, salt, file, "public/uploads/" + uuid);
        new EncryptedFile(file.getName(), uuid, file.length(), salt, hash, hmac).save();
        index();
    }

    public static void get(String uuid) {
        render();
    }

    public static void decrypt(String uuid, String password) throws Exception {
        EncryptedFile encryptedFile = EncryptedFile.find("uuid", uuid).first();
        notFoundIfNull(encryptedFile);
        if (!encryptedFile.hash.equals(CryptoUtils.sha1(password, encryptedFile.salt))) {
            forbidden();
        }

        response.setContentTypeIfNotSet(MimeTypes.getContentType(encryptedFile.name));
        final String hmac = CryptoUtils.decrypt(password, encryptedFile.salt, "public/uploads/" + uuid, response.out);
        if(!hmac.equals(encryptedFile.hmac)){
            error("hmac");
        }
    }

}