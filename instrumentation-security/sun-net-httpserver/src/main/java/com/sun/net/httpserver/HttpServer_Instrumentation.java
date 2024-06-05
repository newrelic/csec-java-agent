package com.sun.net.httpserver;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;


@Weave(originalName = "com.sun.net.httpserver.HttpServer", type = MatchType.BaseClass)
public class HttpServer_Instrumentation {
    public HttpContext createContext (String path, HttpHandler handler){
        HttpContext context;
        try {
            context = Weaver.callOriginal();
        } finally {
            URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(HttpServerHelper.HTTP_METHOD, path, handler.getClass().getName()));
        }
        return context;
    }
}
