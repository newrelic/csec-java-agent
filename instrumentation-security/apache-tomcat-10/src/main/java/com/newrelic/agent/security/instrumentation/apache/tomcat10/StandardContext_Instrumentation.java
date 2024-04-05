package com.newrelic.agent.security.instrumentation.apache.tomcat10;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.catalina.LifecycleException;

import jakarta.servlet.ServletContext;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.catalina.core.StandardContext")
public abstract class StandardContext_Instrumentation {

    public abstract ServletContext getServletContext();

    protected synchronized void startInternal() throws LifecycleException {
        try {
            Weaver.callOriginal();
        } finally {
            HttpServletHelper.gatherURLMappings(getServletContext());
        }
    }
}
