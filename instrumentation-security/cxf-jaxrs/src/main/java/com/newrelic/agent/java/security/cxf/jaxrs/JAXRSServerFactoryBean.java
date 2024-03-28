package com.newrelic.agent.java.security.cxf.jaxrs;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.cxf.endpoint.Server;
import org.apache.cxf.jaxrs.JAXRSServiceFactoryBean;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.cxf.jaxrs.JAXRSServerFactoryBean")
public abstract class JAXRSServerFactoryBean {
    public abstract JAXRSServiceFactoryBean getServiceFactory();

    public Server create() {
        try {
            return Weaver.callOriginal();
        } finally {
            CXFHelper.gatherURLMapping(getServiceFactory().getClassResourceInfo());
        }
    }


}
