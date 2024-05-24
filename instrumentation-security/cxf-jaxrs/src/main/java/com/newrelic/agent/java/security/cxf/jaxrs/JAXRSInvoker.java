package com.newrelic.agent.java.security.cxf.jaxrs;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.StringUtils;
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
                ClassResourceInfo cri = ori.getClassResourceInfo();
                String route = StringUtils.EMPTY;
                if(cri.getURITemplate() != null){
                    route = cri.getURITemplate().getValue();
                }
                if (ori.getURITemplate() != null) {
                    // in case of subresource cri.getURITemplate() will be null
                    route += ori.getURITemplate().getValue();
                }
                NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setEndpointRoute(route);
                // TODO need to consider the case of sub-resource
            }
        } catch (Exception e) {
        }
        return Weaver.callOriginal();
    }
}
