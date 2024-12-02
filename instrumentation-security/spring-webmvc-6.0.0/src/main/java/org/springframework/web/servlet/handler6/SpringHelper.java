package org.springframework.web.servlet.handler6;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.instrumentation.helpers.*;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.util.pattern.PathPattern;

import java.lang.reflect.Method;
import java.util.Iterator;

public class SpringHelper {
    private static final String WILDCARD = "*";
    public static final String SPRING_WEBMVC_600 = "SPRING-WEBMVC-6.0.0";
    public static <T> void gatherURLMappings(T mapping, Method method){
        try {
            if (!NewRelicSecurity.getAgent().isSecurityEnabled()) {
                return;
            }
            RequestMappingInfo mappingInfo = (RequestMappingInfo) mapping;
            PatternsRequestCondition patternsCondition = mappingInfo.getPatternsCondition();
            PathPatternsRequestCondition pathPatternsCondition = mappingInfo.getPathPatternsCondition();
            if (patternsCondition != null) {
                for (String url : patternsCondition.getPatterns()) {
                    if(mappingInfo.getMethodsCondition().getMethods().isEmpty()){
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, url, method.getDeclaringClass().getName()));
                        continue;
                    }
                    for (RequestMethod requestMethod : mappingInfo.getMethodsCondition().getMethods()){
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(requestMethod.name(), url, method.getDeclaringClass().getName()));
                    }
                }
            }
            else if (pathPatternsCondition != null) {
                for (PathPattern url : pathPatternsCondition.getPatterns()) {
                    if (url != null) {
                        if(mappingInfo.getMethodsCondition().getMethods().isEmpty()){
                            URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, url.getPatternString(), method.getDeclaringClass().getName()));
                            continue;
                        }
                        for (RequestMethod requestMethod : mappingInfo.getMethodsCondition().getMethods()){
                            URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(requestMethod.name(), url.getPatternString(), method.getDeclaringClass().getName()));
                        }
                    }
                }
            }
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, SPRING_WEBMVC_600, ignored.getMessage()), ignored, SpringHelper.class.getName());
        }
    }

    public static <T> void setRequestRoute(T mapping) {
        try {
            if (NewRelicSecurity.isHookProcessingActive() && mapping != null && mapping instanceof RequestMappingInfo){
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                if (((RequestMappingInfo) mapping).getPatternsCondition() != null) {
                    Iterator<String> patterns = ((RequestMappingInfo) mapping).getPatternsCondition().getPatterns().iterator();
                    if (patterns.hasNext()) {
                        metaData.getRequest().setRoute(patterns.next());
                    }
                }
                else if (((RequestMappingInfo) mapping).getPathPatternsCondition() != null){
                    Iterator<PathPattern> patterns = ((RequestMappingInfo) mapping).getPathPatternsCondition().getPatterns().iterator();
                    if (patterns.hasNext()) {
                        metaData.getRequest().setRoute(patterns.next().getPatternString());
                    }
                }
                metaData.getMetaData().setFramework(Framework.SPRING_WEB_MVC);
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, SPRING_WEBMVC_600, e.getMessage()), e, SpringHelper.class.getName());
        }
    }
}
