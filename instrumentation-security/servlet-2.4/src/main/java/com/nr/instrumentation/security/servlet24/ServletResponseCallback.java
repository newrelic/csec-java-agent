package com.nr.instrumentation.security.servlet24;

import com.newrelic.api.agent.security.NewRelicSecurity;

import java.util.HashSet;
import java.util.Set;

public class ServletResponseCallback {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SERVLET_OS_OPERATION_LOCK-";
    private static final String RESPONSE_STREAM_OR_WRITER_CALLED = "RESPONSE_STREAM_OR_WRITER_CALLED";
    private static final String RESPONSE_WRITER_HASH = "RESPONSE_WRITER_HASH";
    private static final String RESPONSE_OUTPUTSTREAM_HASH = "RESPONSE_OUTPUTSTREAM_HASH";

    public static final String LF = "\n";

    public static void registerWriterHashIfNeeded(int writerHash){
        try {
            Set<Integer> hashSet = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_WRITER_HASH, Set.class);
            if(hashSet == null){
                hashSet = new HashSet<>();
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_WRITER_HASH, hashSet);
            }
            hashSet.add(writerHash);
        } catch (Throwable ignored) {}
    }

    public static void registerOutputStreamHashIfNeeded(int outputStreamHash){
        try {
            Set<Integer> hashSet = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, Set.class);
            if (hashSet == null) {
                hashSet = new HashSet<>();
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, hashSet);
            }
            hashSet.add(outputStreamHash);
        } catch (Throwable ignored) {}
    }

    public static Boolean processResponseOutputStreamHookData(Integer outputStreamHash) {
        try {
            if(NewRelicSecurity.isHookProcessingActive() && NewRelicSecurity.getAgent().getSecurityMetaData()!= null) {
                Set<Integer> hashSet = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, Set.class);
                if(hashSet != null){
                    return hashSet.contains(outputStreamHash);
                }
            }
        } catch (Throwable ignored) {}
        return false;
    }
}
