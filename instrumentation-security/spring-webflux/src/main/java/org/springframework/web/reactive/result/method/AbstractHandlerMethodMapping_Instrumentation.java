package org.springframework.web.reactive.result.method;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.server.ServerWebExchange;
import java.lang.reflect.Method;

@Weave(type = MatchType.BaseClass, originalName = "org.springframework.web.reactive.result.method.AbstractHandlerMethodMapping")
public abstract class AbstractHandlerMethodMapping_Instrumentation<T> {

    protected void registerHandlerMethod(Object handler, Method method, T mapping) {
        try {
            Weaver.callOriginal();
        } finally {
            SpringHelper.gatherURLMappings(mapping, method);
        }
    }

    protected void handleMatch(T mapping, HandlerMethod handlerMethod, ServerWebExchange exchange) {
        Weaver.callOriginal();
        SpringHelper.getRequestRoute(mapping);
    }
}