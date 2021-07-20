package com.k2cybersecurity.intcodeagent.logging;

import java.io.Serializable;

public class ByteBuffer implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 5693096693182224287L;

    private byte[] byteArray;

    /**
     * @return the byteArray
     */
    public byte[] getByteArray() {
        return byteArray;
    }

    /**
     * @param byteArray the byteArray to set
     */
    public void setByteArray(byte[] byteArray) {
        this.byteArray = byteArray;
    }

    /**
     * @return the limit
     */
    public int getLimit() {
        return limit;
    }

    /**
     * @param limit the limit to set
     */
    public void setLimit(int limit) {
        this.limit = limit;
    }

    private int limit;

    public ByteBuffer() {
    }

    public ByteBuffer(byte[] byteArray, int limit) {
        this.byteArray = byteArray;
        this.limit = limit;
    }
}
