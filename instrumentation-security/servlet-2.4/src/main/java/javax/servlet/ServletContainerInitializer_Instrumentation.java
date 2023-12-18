package javax.servlet;

import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.servlet24.HttpServletHelper;

import java.util.Set;

//@Weave(type = MatchType.Interface, originalName = "javax.servlet.ServletContainerInitializer")
public class ServletContainerInitializer_Instrumentation {
    public void onStartup(Set<Class<?>> c, ServletContext ctx) throws ServletException {
        try {
            Weaver.callOriginal();
        } finally {
            HttpServletHelper.gatherURLMappings(ctx);
        }
    }
}
