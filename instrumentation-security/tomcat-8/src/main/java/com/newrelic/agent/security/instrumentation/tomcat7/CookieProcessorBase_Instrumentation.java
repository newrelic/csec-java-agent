package com.newrelic.agent.security.instrumentation.tomcat7;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.Interface, originalName = "org.apache.tomcat.util.http.CookieProcessorBase")
public abstract class CookieProcessorBase_Instrumentation {

    public void setSameSiteCookies(String sameSiteCookies) {
        Weaver.callOriginal();
        NewRelicSecurity.getAgent().setServerInfo("SAME_SITE_COOKIES", sameSiteCookies);
    }
}
