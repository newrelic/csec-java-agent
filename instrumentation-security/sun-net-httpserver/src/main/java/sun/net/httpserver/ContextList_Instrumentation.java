package sun.net.httpserver;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.sun.net.httpserver.HttpServerHelper;

@Weave(originalName = "sun.net.httpserver.ContextList", type = MatchType.ExactClass)
class ContextList_Instrumentation {

    synchronized HttpContextImpl findContext (String protocol, String path, boolean exact) {
        HttpContextImpl result = Weaver.callOriginal();
        if (result != null) {
            HttpServerHelper.setRoute(result.getPath());
        }
        return result;
    }
}
