package org.usrz.jose.shared;

import java.util.Arrays;

public final class Bytes {

    private final byte[] bytes;

    public Bytes(byte[] bytes) {
        if (bytes == null) throw new NullPointerException("Null bytes");
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    public int length() {
        return bytes.length;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public boolean equals(Object object) {
        if (object == null) return false;
        if (object == this) return true;
        try {
            return Arrays.equals(bytes, ((Bytes)object).bytes);
        } catch (ClassCastException exception) {
            return false;
        }
    }
}
