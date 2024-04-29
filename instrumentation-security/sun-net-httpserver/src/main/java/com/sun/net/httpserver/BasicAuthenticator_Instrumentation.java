package com.sun.net.httpserver;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.BaseClass, originalName = "com.sun.net.httpserver.BasicAuthenticator")
public class BasicAuthenticator_Instrumentation {

    public boolean checkCredentials (String username, String password) {
        ServletHelper.registerUserLevelCode(HttpServerHelper.SUN_NET_HTTP_SERVER);
        return Weaver.callOriginal();
    }

    public Authenticator.Result authenticate (HttpExchange t){
        ServletHelper.registerUserLevelCode(HttpServerHelper.SUN_NET_HTTP_SERVER);
        return Weaver.callOriginal();
    }
}
