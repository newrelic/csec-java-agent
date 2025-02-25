package com.newrelic.agent.security.instrumentation.jetty9;

import com.newrelic.api.agent.security.schema.StringUtils;

import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.List;
import java.util.Map;

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

    public static Map<String, String> getHttpResponseHeaders(HttpServletResponse response) {
        Collection<String> headerNames = response.getHeaderNames();
        Map<String, String> headers = new java.util.HashMap<>();
        headerNames.forEach( headerName -> {
            headers.put(headerName, response.getHeader(headerName));
        });
        return headers;
    }
}
