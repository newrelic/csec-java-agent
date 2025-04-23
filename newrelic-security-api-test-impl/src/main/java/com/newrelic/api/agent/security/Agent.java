package com.newrelic.api.agent.security;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Transaction;
import com.newrelic.api.agent.security.instrumentation.helpers.ThreadLocalLockHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.ServerConnectionConfiguration;
import com.newrelic.api.agent.security.schema.operation.FileIntegrityOperation;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.security.schema.policy.IastDetectionCategory;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

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
    private final IastDetectionCategory defaultIastDetectionCategory = new IastDetectionCategory();

    private AgentPolicy policy = new AgentPolicy();

    private static final Object lock = new Object();

    private final Map<Integer, SecurityMetaData> securityMetaDataMap = new ConcurrentHashMap<>();

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
    public IastDetectionCategory getIastDetectionCategory() {
        return defaultIastDetectionCategory;
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
        if (ThreadLocalLockHelper.isLockHeldByCurrentThread()) {
            return;
        }
        if (operation.isLowSeverityHook() && operation instanceof FileOperation ){
            List<String> fileNames = ((FileOperation) operation).getFileName();
            if (!fileNames.isEmpty() && !fileNames.get(0).startsWith("/tmp/test-")) {
                return;
            }
        }
        System.out.println("Registering operation : " + operation.hashCode() + " : " + NewRelic.getAgent().getTransaction().hashCode());
        String apiId = "dummy-api-id";
        if(operation instanceof FileIntegrityOperation && ((FileIntegrityOperation) operation).getFileName().endsWith(".new.class")){
            return;
        }
        operation.setApiID(apiId);
        String executionId = "dummy-exec-id";
        operation.setExecutionId(executionId);
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

    @Override
    public String getServerInfo(String key) {
        return null;
    }

    @Override
    public void setApplicationConnectionConfig(int port, String scheme) {
        //TODO Ishika please fill this as per your needs
    }

    @Override
    public ServerConnectionConfiguration getApplicationConnectionConfig(int port) {
        return null;
    }

    @Override
    public Map<Integer, ServerConnectionConfiguration> getApplicationConnectionConfig() {
        //TODO Ishika please fill this as per your needs
        return null;
    }

    @Override
    public void log(LogLevel logLevel, String event, Throwable throwableEvent, String logSourceClassName) {

    }

    @Override
    public void log(LogLevel logLevel, String event, String logSourceClassName) {

    }

    @Override
    public void reportIncident(LogLevel logLevel, String event, Throwable exception, String caller) {

    }

    @Override
    public void reportIASTScanFailure(SecurityMetaData securityMetaData, String apiId, Throwable exception, String nrCsecFuzzRequestId, String controlCommandId, String failureMessage) {

    }

    @Override
    public void retransformUninstrumentedClass(Class<?> classToRetransform) {

    }

    @Override
    public String decryptAndVerify(String encryptedData, String hashVerifier) {
        return null;
    }

    @Override
    public void reportApplicationRuntimeError(SecurityMetaData securityMetaData, Throwable exception) {

    }

    @Override
    public boolean recordExceptions(SecurityMetaData securityMetaData, Throwable exception) {
        return false;
    }

    @Override
    public void reportURLMapping() {

    }

    @Override
    public void dispatcherTransactionStarted() {
    }

    @Override
    public void dispatcherTransactionCancelled() {
    }

    @Override
    public void dispatcherTransactionFinished() {
    }
}