package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.api.agent.security.schema.ApplicationURLMapping;

import java.util.Set;

public class ApplicationURLMappings extends AgentBasicInfo{

    private Set<ApplicationURLMapping> applicationURLMappings;

    public ApplicationURLMappings(Set<ApplicationURLMapping> applicationURLMappings) {
        this.applicationURLMappings = applicationURLMappings;
    }

    public Set<ApplicationURLMapping> getApplicationURLMappings() {
        return applicationURLMappings;
    }

    public void setApplicationURLMappings(Set<ApplicationURLMapping> applicationURLMappings) {
        this.applicationURLMappings = applicationURLMappings;
    }
}
