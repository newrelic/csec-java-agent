package org.jboss.resteasy.core;

import com.newrelic.agent.security.instrumentation.resteasy3.RestEasyHelper;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.jboss.resteasy.spi.HttpRequest;

import java.util.regex.Matcher;

@Weave(originalName = "org.jboss.resteasy.core.registry.MethodExpression")
public abstract class MethodExpression_Instrumentation {
    public abstract String getPathExpression();
    public void populatePathParams(HttpRequest request, Matcher matcher, String path){
        Weaver.callOriginal();
        RestEasyHelper.getRequestRoute(getPathExpression(), path);
    }
}