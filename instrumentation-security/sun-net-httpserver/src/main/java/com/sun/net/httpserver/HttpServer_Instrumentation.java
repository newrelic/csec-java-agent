package com.sun.net.httpserver;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;


@Weave(originalName = "com.sun.net.httpserver.HttpServer", type = MatchType.BaseClass)
public class HttpServer_Instrumentation {

    public HttpContext createContext (String path, HttpHandler handler){
        HttpContext context = Weaver.callOriginal();
        try {
            URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(HttpServerHelper.HTTP_METHOD, path, handler.getClass().getName()));
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, HttpServerHelper.SUN_NET_HTTPSERVER, e.getMessage()), e, this.getClass().getName());
        }
        return context;
    }

    public void removeContext (String path) throws IllegalArgumentException {
        Weaver.callOriginal();
        try {
            URLMappingsHelper.removeApplicationURLMapping(HttpServerHelper.HTTP_METHOD, path);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_REMOVING_APP_ENDPOINTS, HttpServerHelper.SUN_NET_HTTPSERVER, e.getMessage()), e, this.getClass().getName());
        }
    }

    public void removeContext (HttpContext context) {
        Weaver.callOriginal();
        try {
            URLMappingsHelper.removeApplicationURLMapping(HttpServerHelper.HTTP_METHOD, context.getPath());
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_REMOVING_APP_ENDPOINTS, HttpServerHelper.SUN_NET_HTTPSERVER, e.getMessage()), e, this.getClass().getName());
        }
    }
}
