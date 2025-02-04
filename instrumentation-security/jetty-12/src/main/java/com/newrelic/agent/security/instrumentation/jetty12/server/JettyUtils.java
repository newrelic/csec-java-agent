package com.newrelic.agent.security.instrumentation.jetty12.server;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.StringUtils;
import org.eclipse.jetty.server.Response;

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

    public static void processResponseHeaders(Response jettyResponse, HttpResponse response) {
        jettyResponse.getHeaders().forEach(header -> {
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getHeaders().put(header.getName(), header.getValue());
            if(StringUtils.equalsAny(StringUtils.lowerCase(header.getName()), "content-type", "contenttype")){
                response.setContentType(header.getValue());
            }
        });
    }
}
