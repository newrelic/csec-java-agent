package org.springframework.web.servlet.handler530;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;

@Weave(type = MatchType.BaseClass, originalName = "org.springframework.web.servlet.handler.AbstractHandlerMethodMapping")
public abstract class AbstractHandlerMethodMapping_Instrumentation<T> {

    protected void registerHandlerMethod(Object handler, Method method, T mapping) {
        try {
            Weaver.callOriginal();
        } finally {
            SpringHelper.gatherURLMappings(mapping, method);
        }
    }
    protected void handleMatch(T mapping, String lookupPath, HttpServletRequest request) {
        Weaver.callOriginal();
        SpringHelper.setRequestRoute(mapping);
    }
}