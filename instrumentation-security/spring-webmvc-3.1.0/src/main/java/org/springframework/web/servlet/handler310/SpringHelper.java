package org.springframework.web.servlet.handler310;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.instrumentation.helpers.*;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.util.Iterator;

public class SpringHelper {
    public static <T> void gatherURLMappings(T mapping){
        try {
            RequestMappingInfo mappingInfo = (RequestMappingInfo) mapping;
            PatternsRequestCondition patternsCondition = mappingInfo.getPatternsCondition();
            if (patternsCondition != null) {
                for (RequestMethod method : mappingInfo.getMethodsCondition().getMethods()) {
                    for (String url : patternsCondition.getPatterns()) {
                        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(method.name(), url));
                    }
                }
            }
        } catch (Throwable ignored){
        }
    }
}
