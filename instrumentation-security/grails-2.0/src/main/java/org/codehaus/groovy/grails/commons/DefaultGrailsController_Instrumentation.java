package org.codehaus.groovy.grails.commons;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.grails2.GrailsHelper;

import java.util.Map;

@Weave(type = MatchType.ExactClass, originalName = "org.codehaus.groovy.grails.commons.DefaultGrailsControllerClass")
public abstract class DefaultGrailsController_Instrumentation {

    public abstract Class<?> getClazz();

    private Map<String, String> uri2viewMap = Weaver.callOriginal();

    public void initialize() {
        try {
            Weaver.callOriginal();
        } finally {
            GrailsHelper.gatherUrlMappings(uri2viewMap, getClazz().getName());
        }
    }
}
