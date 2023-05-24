package org.springframework.web.reactive.result.method;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.result.condition.PatternsRequestCondition;
import org.springframework.web.util.pattern.PathPattern;

import java.util.Iterator;

public class SpringHelper {
    public static <T> void gatherURLMappings(T mapping){
        try {
            RequestMappingInfo mappingInfo = (RequestMappingInfo) mapping;
            for (RequestMethod requestMethod : mappingInfo.getMethodsCondition().getMethods()) {
                PatternsRequestCondition patternsCondition = mappingInfo.getPatternsCondition();
                for (PathPattern url : patternsCondition.getPatterns()) {
                    NewRelicSecurity.getAgent().addURLMapping(new ApplicationURLMapping(requestMethod.name(), url.getPatternString()));
                }
            }
        } catch (Throwable ignored){
        }
    }
}
