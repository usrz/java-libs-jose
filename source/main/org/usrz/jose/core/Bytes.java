package org.usrz.jose.core;

import java.util.Arrays;

public final class Bytes {

    private final byte[] bytes;

    public Bytes(byte[] bytes) {
        if (bytes == null) throw new NullPointerException("Null bytes");
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        final byte[] array = new byte[bytes.length];
        System.arraycopy(bytes, 0, array, 0, bytes.length);
        return array;
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
