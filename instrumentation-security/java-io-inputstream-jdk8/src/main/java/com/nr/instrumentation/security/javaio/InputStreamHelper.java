package com.nr.instrumentation.security.javaio;

import com.newrelic.api.agent.security.NewRelicSecurity;

import java.util.Set;

public class InputStreamHelper {


    private static final String REQUEST_INPUTSTREAM_HASH = "REQUEST_INPUTSTREAM_HASH";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SERVLET_IS_OPERATION_LOCK-";

    public static final String LF = "\n";

    public static Boolean processRequestInputStreamHookData(Integer inputStreamHash) {
        try {
            if(NewRelicSecurity.isHookProcessingActive() && NewRelicSecurity.getAgent().getSecurityMetaData()!= null) {
                Set<Integer> hashSet = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_INPUTSTREAM_HASH, Set.class);
                if(hashSet != null){
                    return hashSet.contains(inputStreamHash);
                }
            }
        } catch (Throwable ignored){}
        return false;
    }

}
