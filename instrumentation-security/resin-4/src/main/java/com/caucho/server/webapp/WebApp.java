package com.caucho.server.webapp;

import com.newrelic.agent.security.instrumentation.resin4.HttpServletHelper;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave
public abstract class WebApp extends ServletContextImpl{

    public void init() {
        Weaver.callOriginal();
        HttpServletHelper.gatherURLMappings(this);
    }
}
