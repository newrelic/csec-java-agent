package org.glassfish.jersey.server.internal;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.jersey.JerseyHelper;
import org.glassfish.jersey.server.model.ResourceModel;


@Weave(type = MatchType.ExactClass, originalName = "org.glassfish.jersey.server.internal.JerseyResourceContext")
public class JerseyResourceContext_Instrumentation {

    public void setResourceModel(ResourceModel resourceModel) {
        try {
            Weaver.callOriginal();
        } finally {
            JerseyHelper.gatherUrlMappings(resourceModel);
        }
    }
}
