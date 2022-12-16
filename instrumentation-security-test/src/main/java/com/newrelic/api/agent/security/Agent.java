package com.newrelic.api.agent.security;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.utils.*;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Transaction;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;

import java.time.Instant;

public class Agent implements SecurityAgent {

    private static Agent instance;

    private static AgentPolicy policy = new AgentPolicy();

    private static Object lock = new Object();

    private java.net.URL agentJarURL;

    public static SecurityAgent getInstance() {
        if(instance == null) {
            synchronized (lock){
                if(instance == null){
                    instance = new Agent();
                }
            }
        }
        return instance;
    }

    private Agent(){
    }

    private void initialise() {
    }

    @Override
    public boolean refreshState(java.net.URL agentJarURL) {
        return true;
    }

    @Override
    public boolean deactivateSecurity() {
        return true;
    }

    @Override
    public String registerOperation(AbstractOperation operation) {
        String executionId = ExecutionIDGenerator.getExecutionId();
        operation.setExecutionId(executionId);
        operation.setStartTime(Instant.now().toEpochMilli());
        operation.setStackTrace(Thread.currentThread().getStackTrace());
        SecurityInstrumentationTestRunner.getIntrospector().addExitEvent(operation);
        return executionId;
    }

    @Override
    public void registerExitEvent(AbstractOperation operation) {
        if (operation == null) {
            return;
        }
        K2RequestIdentifier k2RequestIdentifier = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier();

        ExitEventBean exitEventBean = new ExitEventBean(operation.getExecutionId(), operation.getCaseType().getCaseType());
        exitEventBean.setK2RequestIdentifier(k2RequestIdentifier.getRaw());
        AgentInfo.getInstance().getJaHealthCheck().incrementExitEventSentCount();
        SecurityInstrumentationTestRunner.getIntrospector().addExitEvent(exitEventBean);
    }

    @Override
    public boolean isSecurityActive() {
        return true;
    }

    @Override
    public AgentPolicy getCurrentPolicy() {
        return policy;
    }

    public static void setPolicy(AgentPolicy policy) {
        Agent.policy = policy;
    }

    @Override
    public SecurityMetaData getSecurityMetaData() {
        if(!isSecurityActive()){
            return null;
        }
        try {
            Transaction tx = NewRelic.getAgent().getTransaction();
            if (tx != null) {
                Object meta = tx.getSecurityMetaData();
                if (meta instanceof SecurityMetaData) {
                    return (SecurityMetaData) meta;
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String getAgentUUID() {
        return "DUMMY_UUID";
    }

}