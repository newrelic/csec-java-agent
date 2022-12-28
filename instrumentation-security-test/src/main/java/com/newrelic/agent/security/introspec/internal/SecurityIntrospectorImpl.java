package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;

import java.util.List;

public class SecurityIntrospectorImpl implements SecurityIntrospector {
    @Override
    public List<AbstractOperation> getOperations() {
        return (List<AbstractOperation>) NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(Agent.OPERATIONS, List.class);
    }

    @Override
    public List<ExitEventBean> getExitEvents() {
        return (List<ExitEventBean>) NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(Agent.EXIT_OPERATIONS, List.class);
    }


    @Override
    public void clear() {
        NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(Agent.OPERATIONS, List.class).clear();
        NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(Agent.EXIT_OPERATIONS, List.class).clear();
    }
}