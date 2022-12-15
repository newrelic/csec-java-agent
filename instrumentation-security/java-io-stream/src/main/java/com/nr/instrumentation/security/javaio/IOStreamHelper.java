package com.nr.instrumentation.security.javaio;

import com.newrelic.api.agent.security.NewRelicSecurity;

public class IOStreamHelper {


    private static final String REQUEST_READER_HASH = "REQUEST_READER_HASH";

    private static final String RESPONSE_WRITER_HASH = "RESPONSE_WRITER_HASH";
    private static final String RESPONSE_OUTPUTSTREAM_HASH = "RESPONSE_OUTPUTSTREAM_HASH";

    public static final String LF = "\n";


    public static Boolean processRequestReaderHookData(Integer readerHash) {
        return readerHash.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_READER_HASH, Integer.class));
    }

    public static Boolean processResponseWriterHookData(Integer writerHash) {
        return writerHash.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_WRITER_HASH, Integer.class));
    }

    public static Boolean processResponseOutputStreamHookData(Integer outputStreamHash) {
        Integer x = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, Integer.class);
//        System.out.println("Hooking enabled for " + x + " : " + inputStreamHash);
        return outputStreamHash.equals(x);
    }
}
