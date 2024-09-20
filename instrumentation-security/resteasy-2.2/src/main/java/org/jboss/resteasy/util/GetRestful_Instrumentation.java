package org.jboss.resteasy.util;

import com.newrelic.agent.security.instrumentation.resteasy2.RestEasyHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.ArrayList;
import java.util.List;

@Weave(originalName = "org.jboss.resteasy.util.GetRestful")
public class GetRestful_Instrumentation {

    private static boolean hasJAXRSAnnotations(Class<?> c){
        boolean result = Weaver.callOriginal();
        if (NewRelicSecurity.isHookProcessingActive() && Boolean.TRUE.equals(result)){
            SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            List<String> subResourceList = metaData.getCustomAttribute(RestEasyHelper.RESTEASY_SUB_RESOURCE_LIST, List.class);
            if (subResourceList == null) {
                subResourceList = new ArrayList<>();
            }
            subResourceList.add(c.getName());
            metaData.addCustomAttribute(RestEasyHelper.RESTEASY_SUB_RESOURCE_LIST, subResourceList);
        }
        return result;
    }

}
