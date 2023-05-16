package security.org.eclipse.jetty11.server;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Request;

@Weave(type = MatchType.Interface, originalName = "org.eclipse.jetty.server.Handler")
public abstract class Handler_Instrumentation {
    public void handle(String var1, Request var2, HttpServletRequest var3, HttpServletResponse var4) {
        ServletHelper.registerUserLevelCode("jetty-handle");
        Weaver.callOriginal();
    }
}
