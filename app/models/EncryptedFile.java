package models;

import play.db.jpa.Model;

import javax.persistence.Entity;

@Entity
public class EncryptedFile extends Model {

    public String name;

    public String uuid;

    public Long size;

    public String salt;

    public String hash;

    public String hmac;

    public EncryptedFile(String name, String uuid, Long size, String salt, String hash, String hmac) {
        this.name = name;
        this.uuid = uuid;
        this.size = size;
        this.salt = salt;
        this.hash = hash;
        this.hmac = hmac;
    }

    @Override
    public String toString() {
        return "EncryptedFile{" +
                "name='" + name + '\'' +
                ", uuid='" + uuid + '\'' +
                ", salt='" + salt + '\'' +
                ", hash='" + hash + '\'' +
                ", hmac='" + hmac + '\'' +
                '}';
    }
}
