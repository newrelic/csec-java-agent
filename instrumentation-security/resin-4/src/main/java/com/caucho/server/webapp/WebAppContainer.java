package com.caucho.server.webapp;

import com.newrelic.agent.security.instrumentation.resin4.HttpServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.BaseClass)
public class WebAppContainer {

    public WebAppController[] getWebAppList() {
        return Weaver.callOriginal();
    }

    public void start() {
        Weaver.callOriginal();
        HttpServletHelper.gatherURLMappings(getWebAppList());
    }

}
