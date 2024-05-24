package org.glassfish.jersey.uri;

import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(originalName = "org.glassfish.jersey.uri.PathPattern")
public final class PathPattern_Instrumentation extends PatternWithGroups_Instrumentation{
    public UriTemplate getTemplate() {
        return Weaver.callOriginal();
    }
}
