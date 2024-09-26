package com.newrelic.agent.security;

import com.newrelic.agent.security.instrumentator.httpclient.RestRequestThreadPool;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.instrumentator.utils.ApplicationInfoUtils;
import com.newrelic.agent.security.instrumentator.utils.INRSettingsKey;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ApplicationInfoBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.Identifier;
import com.newrelic.agent.security.intcodeagent.models.javaagent.JAHealthCheck;
import com.newrelic.agent.security.intcodeagent.properties.BuildInfo;
import com.newrelic.agent.security.intcodeagent.websocket.WSUtils;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.newrelic.agent.security.intcodeagent.logging.IAgentConstants.VMPID_SPLIT_CHAR;
import static com.newrelic.agent.security.util.IUtilConstants.NOT_AVAILABLE;

public class AgentInfo {

    private static final String APP_INFO_BEAN_NOT_CREATED = "[APP_INFO] Error application info bean not created.";

    private static final Object lock = new Object();

    private ApplicationInfoBean applicationInfo;

    private JAHealthCheck jaHealthCheck;

    private final Integer VMPID;

    private Identifier identifier;

    private final String applicationUUID;

    private boolean isAgentActive = false;

    private Map<String, String> linkingMetadata = new HashMap<>();

    private BuildInfo buildInfo = new BuildInfo();

    private static FileLoggerThreadPool logger;
    private boolean processProtected = false;

    private AgentInfo() {
        RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
        String runningVM = runtimeMXBean.getName();
        VMPID = Integer.parseInt(runningVM.substring(0, runningVM.indexOf(VMPID_SPLIT_CHAR)));
//        osVariables = OsVariablesInstance.getInstance().getOsVariables();
        if (NewRelic.getAgent().getConfig().getValue("security.debug.application_uuid") != null){
            applicationUUID = NewRelic.getAgent().getConfig().getValue("security.debug.application_uuid");
        } else {
            applicationUUID = UUID.randomUUID().toString();
        }
    }

    private static final class InstanceHolder {
        static final AgentInfo instance = new AgentInfo();
    }

    public static AgentInfo getInstance(){
        return InstanceHolder.instance;
    }

    public void initialiseHC(){
        jaHealthCheck = new JAHealthCheck(applicationUUID);
    }

    public ApplicationInfoBean getApplicationInfo() {
        return applicationInfo;
    }

    public JAHealthCheck getJaHealthCheck() {
        return jaHealthCheck;
    }

    public Integer getVMPID() {
        return VMPID;
    }

    public Identifier getIdentifier() {
        return identifier;
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public Map<String, String> getLinkingMetadata() {
        return linkingMetadata;
    }

    public void setIdentifier(Identifier identifier) {
        this.identifier = identifier;
    }

    public void setLinkingMetadata(Map<String, String> linkingMetadata) {
        this.linkingMetadata = linkingMetadata;
    }

    public boolean isAgentActive() {
        return isAgentActive && AgentConfig.getInstance().isNRSecurityEnabled();
    }

    public void setAgentActive(boolean agentActive) {
        isAgentActive = agentActive;
    }

    public BuildInfo getBuildInfo() {
        return buildInfo;
    }

    public void setBuildInfo(BuildInfo buildInfo) {
        this.buildInfo = buildInfo;
    }

    public static void initialiseLogger() {
        logger = FileLoggerThreadPool.getInstance();
    }

    public ApplicationInfoBean generateAppInfo(CollectorConfig config) {
        applicationInfo = ApplicationInfoUtils.createApplicationInfoBean(identifier, getVMPID(), applicationUUID, config);
        if (applicationInfo == null) {
            // TODO raise exception
            logger.logInit(
                    LogLevel.SEVERE,
                    APP_INFO_BEAN_NOT_CREATED,
                    AgentInfo.class.getName()
            );
        }
        return applicationInfo;
    }

    public void initStatusLogValues() {
        AgentUtils.getInstance().getStatusLogValues().put("start-time", Instant.now().toString());
        AgentUtils.getInstance().getStatusLogValues().put("application-uuid", applicationUUID);
        AgentUtils.getInstance().getStatusLogValues().put("pid", VMPID.toString());
        AgentUtils.getInstance().getStatusLogValues().put("java-version", String.format("%s (%s) (build %s)", System.getProperty("java.runtime.name"), System.getProperty("java.vendor"), System.getProperty("java.runtime.version")));
        AgentUtils.getInstance().getStatusLogValues().put("java-binary", ManagementFactory.getRuntimeMXBean().getName());
        File cwd = new File(".");
        AgentUtils.getInstance().getStatusLogValues().put("cwd", cwd.getAbsolutePath());
        AgentUtils.getInstance().getStatusLogValues().put("cwd-permissions", String.valueOf(cwd.canWrite() && cwd.canRead()));
        AgentUtils.getInstance().getStatusLogValues().put("server-name", NOT_AVAILABLE);
        AgentUtils.getInstance().getStatusLogValues().put("app-location", NOT_AVAILABLE);
        AgentUtils.getInstance().getStatusLogValues().put("framework", NOT_AVAILABLE);
    }

    public boolean agentStatTrigger(boolean clean){
        boolean state = true;
        if(StringUtils.isBlank(getLinkingMetadata().getOrDefault(INRSettingsKey.NR_ENTITY_GUID, StringUtils.EMPTY))){
            logger.log(LogLevel.WARNING, "NewRelic security Agent INACTIVE!!! since entity.guid is not known.", AgentInfo.class.getName());
            state = false;
        }
        else if(StringUtils.isBlank(getLinkingMetadata().getOrDefault(INRSettingsKey.AGENT_RUN_ID_LINKING_METADATA, StringUtils.EMPTY))){
            logger.log(LogLevel.WARNING, "NewRelic security Agent INACTIVE!!! since agentRunId is not known.", AgentInfo.class.getName());
            state = false;
        }
        else if (!AgentConfig.getInstance().isNRSecurityEnabled()) {
            logger.log(LogLevel.WARNING, "NewRelic security Agent INACTIVE!!! since security config is disabled.", AgentInfo.class.getName());
            state = false;
        } else if (!WSUtils.isConnected()) {
            logger.log(LogLevel.WARNING, "NewRelic security Agent INACTIVE!!! Can't connect with Security Engine.", AgentInfo.class.getName());
            state = false;
        }
        if(state) {
            logger.logInit(LogLevel.INFO, String.format("Security Agent is now ACTIVE for %s", applicationUUID), AgentInfo.class.getName());
        } else if(clean) {
            RestRequestThreadPool.getInstance().resetIASTProcessing();
            GrpcClientRequestReplayHelper.getInstance().resetIASTProcessing();
        }

        if(state && !processProtected){
            processProtected = true;
            System.out.printf("This application instance is now being protected by New Relic Security under id %s\n", getApplicationUUID());
        }
        setAgentActive(state);
        return state;
    }
}
