package com.newrelic.agent.security.instrumentation.tomcat7;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.File;

@Weave(type = MatchType.Interface, originalName = "org.apache.catalina.Container")
public abstract class Container_Instrumentation {

    public File getCatalinaBase() {
        File returnValue = Weaver.callOriginal();
        if(returnValue != null) {
            NewRelicSecurity.getAgent().setServerInfo("APPLICATION_DIRECTORY", returnValue.getAbsolutePath());
        }
        return returnValue;
    }

}
