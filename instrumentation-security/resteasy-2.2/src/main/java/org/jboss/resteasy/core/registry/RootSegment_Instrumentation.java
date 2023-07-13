package org.jboss.resteasy.core.registry;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.resteasy2.RestEasyHelper;
import org.jboss.resteasy.core.ResourceInvoker;

@Weave(type = MatchType.ExactClass, originalName = "org.jboss.resteasy.core.registry.RootSegment")
public class RootSegment_Instrumentation {
    public void addPath(String path, ResourceInvoker invoker){
        try {
            Weaver.callOriginal();
        } finally {
            postProcessing(path, invoker);
        }
    }

    private void postProcessing(String path, ResourceInvoker invoker) {
        try {
            RestEasyHelper.gatherUrlMappings(path, invoker);
        } catch (Throwable ignored) {
        }
    }
}
