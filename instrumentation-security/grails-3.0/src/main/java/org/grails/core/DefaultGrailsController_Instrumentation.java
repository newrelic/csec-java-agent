package org.grails.core;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.grails3.GrailsHelper;

import java.lang.reflect.Method;
import java.util.Map;

@Weave(type = MatchType.ExactClass, originalName = "org.grails.core.DefaultGrailsControllerClass")
public abstract class DefaultGrailsController_Instrumentation {

    private Map<String, Method> actions = Weaver.callOriginal();

    abstract public Class<?> getClazz();

    abstract public String getName();

    @WeaveAllConstructors
    public DefaultGrailsController_Instrumentation() {
        GrailsHelper.gatherUrlMappings(actions, getClazz().getName(), getName());
    }

    public Object invoke(Object controller, String action) throws Throwable {
        GrailsHelper.setRoute(getName(), action);
        return Weaver.callOriginal();
    }
}
