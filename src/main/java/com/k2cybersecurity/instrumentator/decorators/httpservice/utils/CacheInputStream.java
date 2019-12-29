package com.k2cybersecurity.instrumentator.decorators.httpservice.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class CacheInputStream extends InputStream {

    private ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    private InputStream streamToCache;

    public CacheInputStream(InputStream streamToCache) {
        this.streamToCache = streamToCache;
    }

    @Override
    public int read() throws IOException {
        int i = streamToCache.read();
        byteArrayOutputStream.write(i);
        return i;
    }

    public byte[] readCurrentCache() {
        return byteArrayOutputStream.toByteArray();
    }
}
