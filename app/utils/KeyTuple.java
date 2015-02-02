package utils;

import java.util.Arrays;

public final class KeyTuple {

    public final byte[] key;

    public final byte[] left;

    public final byte[] right;

    public KeyTuple(byte[] key) {
        this.key = key;

        this.left = Arrays.copyOfRange(key, 0, key.length / 2);
        this.right = Arrays.copyOfRange(key, key.length / 2, key.length);
    }
}
