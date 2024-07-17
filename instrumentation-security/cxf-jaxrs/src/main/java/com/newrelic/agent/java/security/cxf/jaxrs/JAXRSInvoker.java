package com.newrelic.agent.java.security.cxf.jaxrs;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.cxf.jaxrs.model.ClassResourceInfo;
import org.apache.cxf.jaxrs.model.OperationResourceInfo;
import org.apache.cxf.message.Exchange;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.cxf.jaxrs.JAXRSInvoker")
public class JAXRSInvoker {
    public Object invoke(Exchange exchange, Object request) {
        try {
            OperationResourceInfo ori = exchange.get(OperationResourceInfo.class);
            if(NewRelicSecurity.isHookProcessingActive() && ori != null) {
                SecurityMetaData metaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                metaData.getRequest().setRoute(CXFHelper.getRequestRoute(ori));
                metaData.getMetaData().setFramework(Framework.CXF_JAXRS);
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_GETTING_ROUTE_FOR_INCOMING_REQUEST, CXFHelper.CXF_JAX_RS, e.getMessage()), e, this.getClass().getName());
        }
        return Weaver.callOriginal();
    }
}
