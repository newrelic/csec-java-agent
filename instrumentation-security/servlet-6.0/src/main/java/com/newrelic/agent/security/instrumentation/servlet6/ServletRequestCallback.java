package com.newrelic.agent.security.instrumentation.servlet6;

import com.newrelic.api.agent.security.NewRelicSecurity;

import java.util.HashSet;
import java.util.Set;

public class ServletRequestCallback {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SERVLET_IS_OPERATION_LOCK-";

    private static final String REQUEST_READER_HASH = "REQUEST_READER_HASH";

    private static final String REQUEST_INPUTSTREAM_HASH = "REQUEST_INPUTSTREAM_HASH";

    public static void registerReaderHashIfNeeded(int readerHash){
        try {
            Set<Integer> hashSet = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_READER_HASH, Set.class);
            if(hashSet == null){
                hashSet = new HashSet<>();
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_READER_HASH, hashSet);
            }
            hashSet.add(readerHash);
        } catch (Throwable ignored) {}
    }

    public static void registerInputStreamHashIfNeeded(int inputStreamHash){
        try {
            Set<Integer> hashSet = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_INPUTSTREAM_HASH, Set.class);
            if(hashSet == null){
                hashSet = new HashSet<>();
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(REQUEST_INPUTSTREAM_HASH, hashSet);
            }
            hashSet.add(inputStreamHash);
        } catch (Throwable ignored) {}
    }

    public static Boolean processRequestInputStreamHookData(Integer inputStreamHash) {
        try {
            if(NewRelicSecurity.isHookProcessingActive() && NewRelicSecurity.getAgent().getSecurityMetaData()!= null) {
                Set<Integer> hashSet = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_INPUTSTREAM_HASH, Set.class);
                if(hashSet != null){
                    return hashSet.contains(inputStreamHash);
                }
            }
        } catch (Throwable ignored) {}
        return false;
    }
}
