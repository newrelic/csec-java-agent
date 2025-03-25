package org.glassfish.jersey.server.internal;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.VertxApiEndpointUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.jersey.JerseyHelper;
import org.glassfish.jersey.server.model.ResourceModel;


@Weave(type = MatchType.ExactClass, originalName = "org.glassfish.jersey.server.internal.JerseyResourceContext")
public class JerseyResourceContext_Instrumentation {

    public void setResourceModel(ResourceModel resourceModel) {
        Weaver.callOriginal();
        try {
            JerseyHelper.gatherUrlMappings(resourceModel);
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, JerseyHelper.JERSEY, e.getMessage()), e, this.getClass().getName());
        }
    }
}
