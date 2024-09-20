package javax.servlet;

import com.newrelic.agent.security.instrumentation.servlet30.HttpServletHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import javax.servlet.http.HttpServletRequest;

@Weave(type = MatchType.Interface, originalName = "javax.servlet.Servlet")
public abstract class Servlet_Instrumentation {

    public void service(ServletRequest req, ServletResponse res){
        if (NewRelicSecurity.isHookProcessingActive() && req instanceof HttpServletRequest){
            HttpServletHelper.setRoute((HttpServletRequest) req, NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(), getServletConfig());
        }
        Weaver.callOriginal();
    }

    public abstract ServletConfig getServletConfig();

}
