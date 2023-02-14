package com.nr.instrumentation.security.servlet5;

import com.newrelic.api.agent.security.NewRelicSecurity;

public class ServletResponseCallback {

    private static final String RESPONSE_STREAM_OR_WRITER_CALLED = "RESPONSE_STREAM_OR_WRITER_CALLED";
    private static final String RESPONSE_WRITER_HASH = "RESPONSE_WRITER_HASH";
    private static final String RESPONSE_OUTPUTSTREAM_HASH = "RESPONSE_OUTPUTSTREAM_HASH";

    public static final String LF = "\n";


    public static boolean processHookData() {
        try {
            if(NewRelicSecurity.isHookProcessingActive()
                && (NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_STREAM_OR_WRITER_CALLED, Boolean.class) == null
                    || !NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_STREAM_OR_WRITER_CALLED, Boolean.class))
            ) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_STREAM_OR_WRITER_CALLED, true);
                return true;
            }
        } catch (Throwable ignored){}
        return false;
    }

    public static void registerWriterHashIfNeeded(int writerHash){
        if(processHookData()){
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_WRITER_HASH, writerHash);
        }
    }

    public static void registerOutputStreamHashIfNeeded(int outputStreamHash){
        if(processHookData()){
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, outputStreamHash);
        }
    }

    public static Boolean processResponseOutputStreamHookData(Integer outputStreamHash) {
        return outputStreamHash.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, Integer.class));
    }
}
