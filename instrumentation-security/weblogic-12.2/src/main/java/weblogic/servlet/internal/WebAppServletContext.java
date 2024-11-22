package weblogic.servlet.internal;

import com.newrelic.agent.security.instrumentation.weblogic.HttpServletHelper;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import javax.servlet.ServletRegistration;
import java.util.Map;
import java.util.Set;

@Weave
public final class WebAppServletContext {

    void start() throws Exception {
        Weaver.callOriginal();
        HttpServletHelper.gatherURLMappings(this);
    }

    public Map<String, ? extends ServletRegistration> getServletRegistrations() {
        return Weaver.callOriginal();
    }

    public Set<String> getResourcePaths(String path) {
        return Weaver.callOriginal();
    }
}
