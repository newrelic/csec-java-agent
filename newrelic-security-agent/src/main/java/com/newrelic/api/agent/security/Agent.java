package com.newrelic.api.agent.security;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.dispatcher.EventDispatcher;
import com.newrelic.agent.security.instrumentator.utils.*;
import com.newrelic.agent.security.intcodeagent.constants.AgentServices;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.HealthCheckScheduleThread;
import com.newrelic.agent.security.intcodeagent.schedulers.GlobalPolicyParameterPullST;
import com.newrelic.agent.security.intcodeagent.schedulers.PolicyPullST;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.agent.security.intcodeagent.websocket.WSClient;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Transaction;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.newrelic.agent.security.intcodeagent.logging.IAgentConstants.*;

public class Agent implements SecurityAgent {

    private static final String AGENT_INIT_SUCCESSFUL = "[STEP-2][PROTECTION][COMPLETE] Protecting new process with PID %s and UUID %s : %s.";

    private static final Object lock = new Object();

    private static Agent instance;

    private AgentInfo info;

    private AgentConfig config;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

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
        // TODO: All the record keeping or obj init tasks are to be performed here.
        /**
         * Object initializations
         *      App Info
         *      Health Check
         *      PID detection
         *      Set agent status
         * */
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "off");
        System.setProperty("org.slf4j.simpleLogger.logFile", "System.out");
        config = AgentConfig.getInstance();
        info = AgentInfo.getInstance();
    }

    private void initialise() {
        // TODO: All the bring up tasks are to be performed here.
        /**
         * 1. populate policy
         * 2. create application info
         * 3. initialise health check
         * 4. start following services
         * */

        //NOTE: The bellow call sequence is critical and dependent on each other
        config.instantiate();
        config.setConfig(CollectorConfigurationUtils.populateCollectorConfig());

        info.setIdentifier(ApplicationInfoUtils.envDetection());
        ApplicationInfoUtils.continueIdentifierProcessing(info.getIdentifier(), config.getConfig());
        info.generateAppInfo(config.getConfig());
        info.initialiseHC();
        config.populateAgentPolicy();
        config.populateAgentPolicyParameters();
        config.setupSnapshotDir();
        info.initStatusLogValues();

        startK2Services();
        // log init finish
        logger.logInit(
                LogLevel.INFO,
                String.format(AGENT_INIT_SUCCESSFUL, info.getVMPID(), info.getApplicationUUID(), info.getApplicationInfo()),
                Agent.class.getName()
        );
        populateLinkingMetadata();
        info.agentStatTrigger();
        System.out.println(String.format("This application instance is now being protected by K2 Agent under id %s", info.getApplicationUUID()));
    }

    private void populateLinkingMetadata() {
        Map<String, String> linkingMetaData = NewRelic.getAgent().getLinkingMetadata();
        linkingMetaData.put(INRSettingsKey.AGENT_RUN_ID_LINKING_METADATA, NewRelic.getAgent().getConfig().getValue(INRSettingsKey.AGENT_RUN_ID));
        info.setLinkingMetadata(linkingMetaData);
    }

    private void startK2Services() {
        PolicyPullST.getInstance();
        HealthCheckScheduleThread.getInstance();
        logger.logInit(
                LogLevel.INFO,
                String.format(STARTED_MODULE_LOG, AgentServices.HealthCheck.name()),
                Agent.class.getName()
        );
        tryWebsocketConnection();
        EventSendPool.getInstance();
        logger.logInit(
                LogLevel.INFO,
                String.format(STARTED_MODULE_LOG, AgentServices.EventWritePool.name()),
                Agent.class.getName()
        );
        logger.logInit(LogLevel.INFO, AGENT_INIT_LOG_STEP_FIVE_END, Agent.class.getName());

    }

    private static void tryWebsocketConnection() {
        try {
            int retries = NUMBER_OF_RETRIES;
            WSClient.getInstance().openConnection();
            while (retries > 0) {
                try {
                    if (!WSClient.isConnected()) {
                        retries--;
                        int timeout = (NUMBER_OF_RETRIES - retries);
                        logger.logInit(LogLevel.INFO, String.format("WS client connection failed will retry after %s minute(s)", timeout), Agent.class.getName());
                        TimeUnit.MINUTES.sleep(timeout);
                        WSClient.reconnectWSClient();
                    } else {
                        break;
                    }
                } catch (Throwable e) {
                    logger.log(LogLevel.ERROR, ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET, e,
                            Agent.class.getName());
                    logger.postLogMessageIfNecessary(LogLevel.ERROR, ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET, e,
                            Agent.class.getName());

                }
            }
            if (!WSClient.isConnected()) {
                throw new RuntimeException("Websocket not connected!!!");
            }
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean refreshState(java.net.URL agentJarURL) {
        /**
         * restart k2 services
         **/
        this.agentJarURL = agentJarURL;
        config.setNRSecurityEnabled(false);
        cancelActiveServiceTasks();
        initialise();
        return true;
    }

    private void cancelActiveServiceTasks() {

        /**
         * Websocket
         * policy
         * HealthCheck
         */
        PolicyPullST.getInstance().cancelTask(true);
        GlobalPolicyParameterPullST.getInstance().cancelTask(true);
        HealthCheckScheduleThread.getInstance().cancelTask(true);

    }

    @Override
    public boolean deactivateSecurity() {
        config.setNRSecurityEnabled(false);
        deactivateSecurityServices();
        return true;
    }

    private void deactivateSecurityServices(){
        /**
         * ShutDown following
         * 1. policy + policy parameter
         * 2. websocket
         * 3. event pool
         * 4. HealthCheck
         **/
        PolicyPullST.shutDownPool();
        GlobalPolicyParameterPullST.shutDownPool();
        HealthCheckScheduleThread.shutDownPool();
        WSClient.shutDownWSClient();
        EventSendPool.shutDownPool();
    }

    @Override
    public String registerOperation(AbstractOperation operation) {
        String executionId = ExecutionIDGenerator.getExecutionId();
        operation.setExecutionId(executionId);
        operation.setStartTime(Instant.now().toEpochMilli());
        operation.setStackTrace(Thread.currentThread().getStackTrace());
        System.out.println(JsonConverter.toJSON(operation));
        return executionId;
    }

    @Override
    public void registerExitEvent(String executionId, VulnerabilityCaseType type) {
        EventDispatcher.dispatchExitEvent(executionId, type);
    }

    @Override
    public boolean isSecurityActive() {
        return info.isAgentActive();
    }

    @Override
    public AgentPolicy getCurrentPolicy() {
        return AgentUtils.getInstance().getAgentPolicy();
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

    public AgentInfo getInfo() {
        return info;
    }

    public AgentConfig getConfig() {
        return config;
    }

    public static java.net.URL getAgentJarURL() {
        return instance.agentJarURL;
    }
}