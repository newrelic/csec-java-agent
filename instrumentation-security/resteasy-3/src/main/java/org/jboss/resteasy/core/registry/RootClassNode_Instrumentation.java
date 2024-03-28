package org.jboss.resteasy.core.registry;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.resteasy3.RestEasyHelper;
import org.jboss.resteasy.core.ResourceInvoker;

@Weave(type = MatchType.ExactClass, originalName = "org.jboss.resteasy.core.registry.RootClassNode")
public class RootClassNode_Instrumentation {
    public void addInvoker(String classExpression, String fullpath, ResourceInvoker invoker){
        try {
            Weaver.callOriginal();
        } finally {
            RestEasyHelper.gatherUrlMappings(fullpath, invoker);
        }
    }
}
