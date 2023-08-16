package org.springframework.web.reactive.result.method;

import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.instrumentation.helpers.*;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.result.condition.PatternsRequestCondition;
import org.springframework.web.util.pattern.PathPattern;

public class SpringHelper {
    public static <T> void gatherURLMappings(T mapping){
        try {
            RequestMappingInfo mappingInfo = (RequestMappingInfo) mapping;
            PatternsRequestCondition patternsCondition = mappingInfo.getPatternsCondition();
            if(patternsCondition!=null) {
                for (RequestMethod requestMethod : mappingInfo.getMethodsCondition().getMethods()) {
                    for (PathPattern url : patternsCondition.getPatterns()) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(requestMethod.name(), url.getPatternString()));
                    }
                }
            }
        } catch (Throwable ignored){
        }
    }
}