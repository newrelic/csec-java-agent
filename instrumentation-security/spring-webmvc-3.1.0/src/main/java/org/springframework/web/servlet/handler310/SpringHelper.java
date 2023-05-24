package org.springframework.web.servlet.handler310;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.util.Iterator;

public class SpringHelper {
    public static <T> void gatherURLMappings(T mapping){
        try {
            RequestMappingInfo mappingInfo = (RequestMappingInfo) mapping;
            for (RequestMethod method : mappingInfo.getMethodsCondition().getMethods()) {
                PatternsRequestCondition patternsCondition = mappingInfo.getPatternsCondition();
                if (patternsCondition != null)
                    for (String url : patternsCondition.getPatterns()) {
                        NewRelicSecurity.getAgent().addURLMapping(new ApplicationURLMapping(method.name(), url));
                    }
            }
        } catch (Throwable ignored){
        }
    }
}
