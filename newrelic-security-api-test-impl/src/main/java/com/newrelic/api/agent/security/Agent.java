package com.newrelic.api.agent.security;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Transaction;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Agent implements SecurityAgent {

    public static final String OPERATIONS = "operations";
    public static final String EXIT_OPERATIONS = "exit-operations";
    private static Agent instance;

    private AgentPolicy policy = new AgentPolicy();

    private static final Object lock = new Object();

    private Map<Integer, SecurityMetaData> securityMetaDataMap = new HashMap<>();

    private java.net.URL agentJarURL;

    public static SecurityAgent getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new Agent();
                }
            }
        }
        return instance;
    }

    private Agent() {
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
        System.out.println("Registering operation : " + operation.hashCode() + " : " + NewRelic.getAgent().getTransaction().hashCode());
        String executionId = "dummy-exec-id";
        operation.setExecutionId(executionId);
        operation.setStartTime(Instant.now().toEpochMilli());
        operation.setStackTrace(Thread.currentThread().getStackTrace());
        this.getSecurityMetaData().getCustomAttribute(OPERATIONS, List.class).add(operation);
        return executionId;
    }

    @Override
    public void registerExitEvent(AbstractOperation operation) {
        this.getSecurityMetaData().getCustomAttribute(EXIT_OPERATIONS, List.class).add(operation);
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
        instance.policy = policy;
    }

    @Override
    public SecurityMetaData getSecurityMetaData() {
        if(!isSecurityActive()){
            return null;
        }
        try {
            Transaction tx = NewRelic.getAgent().getTransaction();
            if (tx != null) {
                SecurityMetaData meta = securityMetaDataMap.get(tx.hashCode());
                if (meta == null) {
                    meta = new SecurityMetaData();
                    meta.addCustomAttribute(OPERATIONS, new ArrayList<AbstractOperation>());
                    meta.addCustomAttribute(EXIT_OPERATIONS, new ArrayList<AbstractOperation>());
                    securityMetaDataMap.put(tx.hashCode(), meta);
                }
                populateSecurityData(meta);
                return meta;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return null;
    }

    private void populateSecurityData(SecurityMetaData meta) {
        meta.getRequest().setUrl("/TestUrl");
        meta.getRequest().setMethod("GET");
    }

    @Override
    public String getAgentUUID() {
        return "DUMMY_UUID";
    }

}