package org.springframework.web.servlet.handler310;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.instrumentation.helpers.*;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.lang.reflect.Method;
import java.util.Iterator;

public class SpringHelper {
    private static final String WILDCARD = "*";
    public static final String SPRING_WEBMVC_310 = "SPRING-WEBMVC-3.1.0";
    public static <T> void gatherURLMappings(T mapping, Method method){
        try {
            RequestMappingInfo mappingInfo = (RequestMappingInfo) mapping;
            PatternsRequestCondition patternsCondition = mappingInfo.getPatternsCondition();
            if (patternsCondition != null) {
                for (String url : patternsCondition.getPatterns()) {
                    if (mappingInfo.getMethodsCondition().getMethods().isEmpty()) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, url, method.getDeclaringClass().getName()));
                        continue;
                    }
                    for (RequestMethod requestMethod : mappingInfo.getMethodsCondition().getMethods()) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(requestMethod.name(), url, method.getDeclaringClass().getName()));
                    }
                }
            }
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, SPRING_WEBMVC_310, ignored.getMessage()), ignored, SpringHelper.class.getName());
        }
    }

    public static <T> void setRequestRoute(T mapping) {
        try {
            if (NewRelicSecurity.isHookProcessingActive() && mapping != null && mapping instanceof RequestMappingInfo && ((RequestMappingInfo) mapping).getPatternsCondition() != null){
                Iterator<String> patterns = ((RequestMappingInfo) mapping).getPatternsCondition().getPatterns().iterator();
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                if (patterns.hasNext()) {
                    metaData.getRequest().setRoute(patterns.next());
                    metaData.getMetaData().setFramework(Framework.SPRING_WEB_MVC);
                }
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, SpringHelper.SPRING_WEBMVC_310, e.getMessage()), e, SpringHelper.class.getName());
        }
    }
}
