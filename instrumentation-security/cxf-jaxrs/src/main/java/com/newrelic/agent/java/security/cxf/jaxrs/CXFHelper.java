package com.newrelic.agent.java.security.cxf.jaxrs;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.apache.cxf.jaxrs.model.ClassResourceInfo;
import org.apache.cxf.jaxrs.model.MethodDispatcher;
import org.apache.cxf.jaxrs.model.OperationResourceInfo;

import java.util.List;

public class CXFHelper {
    private static final String EMPTY = "";
    private static final String SEPARATOR = "/";
    private static final String WILDCARD = "*";

    public static void gatherURLMapping(List<ClassResourceInfo> classResourceInfo) {
        for (ClassResourceInfo classResource: classResourceInfo){
            resources(classResource.getURITemplate().getValue(), classResource);
        }
    }

    private static void resources(String segment, ClassResourceInfo classResourceInfo) {
        MethodDispatcher methodDispatcher = classResourceInfo.getMethodDispatcher();
        for(OperationResourceInfo method: methodDispatcher.getOperationResourceInfos()) {
            String segment1 = method.getURITemplate().getValue();
            String path = segment + ((segment.endsWith(SEPARATOR) || segment1.startsWith(SEPARATOR)) ?  EMPTY : SEPARATOR) + segment1;

            // http-method is null, then it can be a sub-resource
            if (method.getHttpMethod() == null){
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(
                        WILDCARD,
                        path + (path.endsWith(SEPARATOR) ? EMPTY : SEPARATOR) + WILDCARD,
                        classResourceInfo.getResourceClass().getName()
                ));
            } else {
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(
                        method.getHttpMethod(),
                        path,
                        classResourceInfo.getResourceClass().getName()
                ));
            }

        }
        // TODO need to update sub-resources case
        // for sub-resources
        for (ClassResourceInfo classResource: classResourceInfo.getSubResources()){
            String segment1 = classResource.getURITemplate().getValue();
            String path = segment + ((segment.endsWith(SEPARATOR) || segment1.startsWith(SEPARATOR)) ?  EMPTY : SEPARATOR) + segment1;
            resources(path, classResource);
        }
    }
}
