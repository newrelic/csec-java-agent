package com.newrelic.agent.security;

import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.instrumentator.utils.ApplicationInfoUtils;
import com.newrelic.agent.security.instrumentator.utils.INRSettingsKey;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ApplicationInfoBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.Identifier;
import com.newrelic.agent.security.intcodeagent.models.javaagent.JAHealthCheck;
import com.newrelic.agent.security.intcodeagent.properties.BuildInfo;
import com.newrelic.agent.security.intcodeagent.websocket.WSClient;
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

    private static final String APP_INFO_BEAN_NOT_CREATED = "[APP_INFO] Error K2 application info bean not created.";

    private static AgentInfo instance;

    private static final Object lock = new Object();

    private ApplicationInfoBean applicationInfo;

    private JAHealthCheck jaHealthCheck;

    private final Integer VMPID;

    private Identifier identifier;

    private final String applicationUUID;

    private boolean isAgentActive = false;

    private Map<String, String> linkingMetadata = new HashMap<>();

    private BuildInfo buildInfo = new BuildInfo();

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private AgentInfo() {
        RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
        String runningVM = runtimeMXBean.getName();
        VMPID = Integer.parseInt(runningVM.substring(0, runningVM.indexOf(VMPID_SPLIT_CHAR)));
//        osVariables = OsVariablesInstance.getInstance().getOsVariables();
        applicationUUID = UUID.randomUUID().toString();
    }

    public static AgentInfo getInstance(){
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new AgentInfo();
                }
            }
        }
        return instance;
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

    public ApplicationInfoBean generateAppInfo(CollectorConfig config) {
        applicationInfo = ApplicationInfoUtils.createApplicationInfoBean(identifier, getVMPID(), applicationUUID, config);
        if (applicationInfo == null) {
            // TODO raise exception
            logger.logInit(
                    LogLevel.ERROR,
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

    public boolean agentStatTrigger(){
        boolean state = true;
        if(StringUtils.isBlank(getLinkingMetadata().getOrDefault(INRSettingsKey.NR_ENTITY_GUID, StringUtils.EMPTY))){
            logger.log(LogLevel.WARN, "K2 security module INACTIVE!!! since entity.guid is not known.", AgentInfo.class.getName());
            state = false;
        }
        else if(StringUtils.isBlank(getLinkingMetadata().getOrDefault(INRSettingsKey.AGENT_RUN_ID_LINKING_METADATA, StringUtils.EMPTY))){
            logger.log(LogLevel.WARN, "K2 security module INACTIVE!!! since agentRunId is not known.", AgentInfo.class.getName());
            state = false;
        }
        else if(!AgentConfig.getInstance().isNRSecurityEnabled()){
            logger.log(LogLevel.WARN, "K2 security module INACTIVE!!! since security config is disabled.", AgentInfo.class.getName());
            state = false;
        }
        else if(!WSClient.isConnected()){
            logger.log(LogLevel.WARN, "K2 security module INACTIVE!!! Can't connect with prevent web agent.", AgentInfo.class.getName());
            state = false;
        }
        if(state) {
            logger.logInit(LogLevel.INFO, String.format("Collector is now ACTIVE for %s", applicationUUID), AgentInfo.class.getName());
        }
        setAgentActive(state);
        return state;
    }
}
