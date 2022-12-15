package com.nr.instrumentation.security.servlet5;

import com.newrelic.api.agent.security.NewRelicSecurity;

public class ServletRequestCallback {

    private static final String REQUEST_STREAM_OR_READER_CALLED = "REQUEST_STREAM_OR_READER_CALLED";
    private static final String REQUEST_READER_HASH = "REQUEST_READER_HASH";

    private static final String REQUEST_INPUTSTREAM_HASH = "REQUEST_INPUTSTREAM_HASH";



    public static boolean processHookData() {
        try {
            if(NewRelicSecurity.isHookProcessingActive()
                && (NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_STREAM_OR_READER_CALLED, Boolean.class) == null
                    || !NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_STREAM_OR_READER_CALLED, Boolean.class))
            ) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_STREAM_OR_READER_CALLED, true);
                return true;
            }
        } catch (Throwable ignored){}
        return false;
    }

    public static void registerReaderHashIfNeeded(int readerHash){
        if(processHookData()){
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_READER_HASH, readerHash);
        }
    }

    public static void registerInputStreamHashIfNeeded(int inputStreamHash){
        if(processHookData()){
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_INPUTSTREAM_HASH, inputStreamHash);
        }
    }

    public static Boolean processRequestInputStreamHookData(Integer inputStreamHash) {
        return inputStreamHash.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_INPUTSTREAM_HASH, Integer.class));
    }
}
