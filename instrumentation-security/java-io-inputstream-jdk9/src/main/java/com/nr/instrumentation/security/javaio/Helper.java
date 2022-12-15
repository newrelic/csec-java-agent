package com.nr.instrumentation.security.javaio;

import com.newrelic.api.agent.security.NewRelicSecurity;

public class Helper {


    private static final String REQUEST_INPUTSTREAM_HASH = "REQUEST_INPUTSTREAM_HASH";

    public static final String LF = "\n";

    public static Boolean processRequestInputStreamHookData(Integer inputStreamHash) {
        Integer x = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_INPUTSTREAM_HASH, Integer.class);
//        System.out.println("Hooking enabled for " + x + " : " + inputStreamHash);
        return inputStreamHash.equals(x);
    }

}
