package org.springframework.web.reactive.result.method;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.instrumentation.helpers.*;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.result.condition.PatternsRequestCondition;
import org.springframework.web.util.pattern.PathPattern;

import java.lang.reflect.Method;
import java.util.Iterator;

public class SpringHelper {
    private static final String WILDCARD = "*";
    public static final String SPRING_WEBFLUX = "SPRING-WEBFLUX";
    public static <T> void gatherURLMappings(T mapping, Method method){
        try {
            if (!NewRelicSecurity.getAgent().isSecurityEnabled()) {
                return;
            }
            RequestMappingInfo mappingInfo = (RequestMappingInfo) mapping;
            PatternsRequestCondition patternsCondition = mappingInfo.getPatternsCondition();
            if (patternsCondition != null) {
                for (PathPattern url : patternsCondition.getPatterns()) {
                    if (mappingInfo.getMethodsCondition().getMethods().isEmpty()) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, url.getPatternString(), method.getDeclaringClass().getName()));
                        continue;
                    }
                    for (RequestMethod requestMethod : mappingInfo.getMethodsCondition().getMethods()) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(requestMethod.name(), url.getPatternString(), method.getDeclaringClass().getName()));
                    }
                }
            }
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, SPRING_WEBFLUX, ignored.getMessage()), ignored, SpringHelper.class.getName());
        }
    }

    public static <T> void getRequestRoute(T mapping) {
        try {
            if (NewRelicSecurity.isHookProcessingActive() && mapping != null && mapping instanceof RequestMappingInfo && ((RequestMappingInfo) mapping).getPatternsCondition() != null && ((RequestMappingInfo) mapping).getPatternsCondition().getPatterns() != null){
                Iterator<PathPattern> patterns = ((RequestMappingInfo) mapping).getPatternsCondition().getPatterns().iterator();
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                if (patterns.hasNext()) {
                    metaData.getRequest().setRoute(patterns.next().getPatternString());
                    metaData.getMetaData().setFramework(Framework.SPRING_WEB_FLUX);
                }
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, SPRING_WEBFLUX, e.getMessage()), e, SpringHelper.class.getName());
        }
    }
}
