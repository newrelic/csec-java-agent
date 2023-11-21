package com.newrelic.api.agent.security;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Transaction;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;

import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Agent implements SecurityAgent {

    public static final String OPERATIONS = "operations";
    public static final String EXIT_OPERATIONS = "exit-operations";
    private static Agent instance;

    private AgentPolicy policy = new AgentPolicy();

    private static final Object lock = new Object();

    private Map<Integer, SecurityMetaData> securityMetaDataMap = new ConcurrentHashMap<>();

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
    public boolean refreshState(URL agentJarURL, Instrumentation instrumentation) {
        return true;
    }

    @Override
    public boolean deactivateSecurity() {
        return true;
    }

    @Override
    public void registerOperation(AbstractOperation operation) {
        System.out.println("Registering operation : " + operation.hashCode() + " : " + NewRelic.getAgent().getTransaction().hashCode());
        String executionId = "dummy-exec-id";
        String apiId = "dummy-api-id";
        operation.setExecutionId(executionId);
        operation.setApiID(apiId);
        operation.setStartTime(Instant.now().toEpochMilli());
        StackTraceElement[] trace = Thread.currentThread().getStackTrace();
        operation.setStackTrace(Arrays.copyOfRange(trace, 1, trace.length));
        this.getSecurityMetaData().getCustomAttribute(OPERATIONS, List.class).add(operation);
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
        int min = 100;
        int max = 5000;
        meta.getRequest().setUrl("/TestUrl"+(int)(Math.random()*(max-min+1)+min));
        meta.getRequest().setMethod("GET");
    }

    @Override
    public String getAgentUUID() {
        return "DUMMY_UUID";
    }

    @Override
    public String getAgentTempDir() {
        return "";
    }

    @Override
    public Instrumentation getInstrumentation() {
        return null;
    }

    @Override
    public boolean isLowPriorityInstrumentationEnabled() {
        return true;
    }

    @Override
    public void setServerInfo(String key, String value) {
        //TODO Ishika please fill this as per your needs
    }
}