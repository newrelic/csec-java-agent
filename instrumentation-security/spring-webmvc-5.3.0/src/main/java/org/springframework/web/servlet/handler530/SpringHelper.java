package org.springframework.web.servlet.handler530;

import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.instrumentation.helpers.*;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.util.pattern.PathPattern;

public class SpringHelper {
    public static <T> void gatherURLMappings(T mapping){
        try {
            RequestMappingInfo mappingInfo = (RequestMappingInfo) mapping;
            PatternsRequestCondition patternsCondition = mappingInfo.getPatternsCondition();
            PathPatternsRequestCondition pathPatternsCondition = mappingInfo.getPathPatternsCondition();
            for (RequestMethod method : mappingInfo.getMethodsCondition().getMethods()) {
                if (patternsCondition != null) {
                    for (String url : patternsCondition.getPatterns()) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(method.name(), url));
                    }
                }
                else if (pathPatternsCondition != null) {
                    for (PathPattern url : pathPatternsCondition.getPatterns()) {
                        if (url != null) {
                            URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(method.name(), url.getPatternString()));
                        }
                    }
                }
            }
        } catch (Throwable ignored){
        }
    }
}
