package com.newrelic.agent.security.instrumentation.tomcat7;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.catalina.core.StandardHost")
public class StandardHost_Instrumentation {

    public String getAppBase() {
        String returnValue = Weaver.callOriginal();
        NewRelicSecurity.getAgent().setServerInfo("APPLICATION_DIRECTORY", returnValue);
        return returnValue;
    }

}
