package com.newrelic.agent.security.instrumentation.jetty12.server;

import com.newrelic.api.agent.security.schema.StringUtils;

import java.util.List;

public class JettyUtils {
    public static String getProtocol(List<String> protocols) {
        if(protocols == null || protocols.isEmpty()){
            return null;
        }

        for (String protocol : protocols){
            return StringUtils.containsIgnoreCase(protocol, "https")? "https" : "http";
        }

        return null;
    }
}
