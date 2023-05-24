package jakarta.servlet;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.servlet5.HttpServletHelper;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

@Weave(type = MatchType.Interface, originalName = "jakarta.servlet.ServletContainerInitializer")
public class ServletContainerInitializer_Instrumentation {
    public void onStartup(Set<Class<?>> var1, ServletContext var2) throws ServletException {
        try {
            Weaver.callOriginal();
        } finally {
            postProcessing(var2);
        }
    }

    private static void postProcessing(ServletContext context) {
        try {
            HttpServletHelper.gatherURLMappings(context);
        } catch (Throwable ignored) {
        }
    }
}
