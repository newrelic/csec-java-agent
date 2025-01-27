package com.opensymphony.xwork2.config;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.apache.struts2.StrutsHelper;
import java.util.List;

@Weave(type = MatchType.Interface, originalName = "com.opensymphony.xwork2.config.Configuration")
public abstract class Configuration_Instrumentation {
    abstract public RuntimeConfiguration getRuntimeConfiguration();

    public List<PackageProvider> reloadContainer(List<ContainerProvider> containerProviders) throws ConfigurationException {
        List<PackageProvider> returnVal;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            StrutsHelper.gatherURLMappings(getRuntimeConfiguration());
        }
        return returnVal;
    }
}
