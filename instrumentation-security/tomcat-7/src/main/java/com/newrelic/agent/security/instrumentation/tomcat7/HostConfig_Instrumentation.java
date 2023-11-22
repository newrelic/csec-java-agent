package com.newrelic.agent.security.instrumentation.tomcat7;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.File;


@Weave(type = MatchType.ExactClass, originalName = "org.apache.catalina.startup.HostConfig")
public class HostConfig_Instrumentation {

    protected File appBase() {
        File returnValue = Weaver.callOriginal();
        if(returnValue != null) {
            NewRelicSecurity.getAgent().setServerInfo("APPLICATION_DIRECTORY", returnValue.getAbsolutePath());
        }
        return returnValue;
    }
}
