package jakarta.servlet;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.servlet6.HttpServletHelper;
import java.util.Set;

//@Weave(type = MatchType.Interface, originalName = "jakarta.servlet.ServletContainerInitializer")
public class ServletContainerInitializer_Instrumentation {
    public void onStartup(Set<Class<?>> var1, ServletContext var2) {
        try {
            Weaver.callOriginal();
        } finally {
            HttpServletHelper.gatherURLMappings(var2);
        }
    }
}
