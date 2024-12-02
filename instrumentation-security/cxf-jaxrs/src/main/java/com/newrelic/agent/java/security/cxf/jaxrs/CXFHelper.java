package com.newrelic.agent.java.security.cxf.jaxrs;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.cxf.jaxrs.model.ClassResourceInfo;
import org.apache.cxf.jaxrs.model.MethodDispatcher;
import org.apache.cxf.jaxrs.model.OperationResourceInfo;

import java.util.List;

public class CXFHelper {

    private static final String WILDCARD = "*";
    public static final String CXF_JAX_RS = "CXF-JAX-RS";

    public static void gatherURLMapping(List<ClassResourceInfo> classResourceInfo) {
        try {
            if (!NewRelicSecurity.getAgent().isSecurityEnabled()) {
                return;
            }
            for (ClassResourceInfo classResource: classResourceInfo){
                resources(classResource.getURITemplate().getValue(), classResource);
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, CXF_JAX_RS, e.getMessage()), e, CXFHelper.class.getName());
        }
    }

    private static void resources(String segment, ClassResourceInfo classResourceInfo) {
        try {
            MethodDispatcher methodDispatcher = classResourceInfo.getMethodDispatcher();
            for (OperationResourceInfo method : methodDispatcher.getOperationResourceInfos()) {
                String segment1 = method.getURITemplate().getValue();
                String path = StringUtils.removeEnd(segment, StringUtils.SEPARATOR) + StringUtils.prependIfMissing(segment1, StringUtils.SEPARATOR);

                // http-method is null, then it can be a sub-resource
                if (method.getHttpMethod() == null) {
                    URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(
                            WILDCARD,
                            StringUtils.appendIfMissing(path, StringUtils.SEPARATOR) + WILDCARD,
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
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_APP_ENDPOINTS, CXF_JAX_RS, e.getMessage()), e, CXFHelper.class.getName());
        }
    }

    public static String getRequestRoute(OperationResourceInfo ori) {
        ClassResourceInfo cri = ori.getClassResourceInfo();
        String route = StringUtils.EMPTY;
        if(cri != null && cri.getURITemplate() != null){
            route = cri.getURITemplate().getValue();
        }
        if (ori.getURITemplate() != null) {
            // in case of subresource cri.getURITemplate() will be null
            route += ori.getURITemplate().getValue();
        }
        if (ori.isSubResourceLocator()){
            route += URLMappingsHelper.subResourceSegment;
        }
        return route;
    }
}
