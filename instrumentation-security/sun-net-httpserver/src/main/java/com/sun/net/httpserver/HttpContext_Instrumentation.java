package com.sun.net.httpserver;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;


@Weave(originalName = "com.sun.net.httpserver.HttpContext", type = MatchType.BaseClass)
public abstract class HttpContext_Instrumentation {
    public abstract String getPath();

    public void setHandler (HttpHandler h) {
        try {
            Weaver.callOriginal();
        } finally {
            URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(HttpServerHelper.HTTP_METHOD, getPath(), h.getClass().getName()));
        }
    }

}
