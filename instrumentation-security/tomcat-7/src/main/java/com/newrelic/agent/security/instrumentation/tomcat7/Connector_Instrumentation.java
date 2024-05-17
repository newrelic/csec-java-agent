package com.newrelic.agent.security.instrumentation.tomcat7;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.catalina.LifecycleException;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.catalina.connector.Connector")
public abstract class Connector_Instrumentation {

    public abstract String getScheme();

    public abstract int getPort();

    protected void startInternal() throws LifecycleException {
        Weaver.callOriginal();
        NewRelicSecurity.getAgent().setApplicationConnectionConfig(getPort(), getScheme());
    }
}
