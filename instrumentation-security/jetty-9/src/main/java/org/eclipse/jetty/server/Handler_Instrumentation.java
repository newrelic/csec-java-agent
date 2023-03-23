package org.eclipse.jetty.server;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Weave(type = MatchType.Interface, originalName = "org.eclipse.jetty.server.Handler")
public abstract class Handler_Instrumentation {
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) {
        ServletHelper.registerUserLevelCode("jetty-handle");
        Weaver.callOriginal();
    }
}
