package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.instrumentator.utils.INRSettingsKey;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;

import static com.newrelic.agent.security.intcodeagent.logging.IAgentConstants.*;


/**
 * The Class AgentBasicInfo.
 */
public class AgentBasicInfo {

    private static final String SCAN_COMPONENT_DATA = "scanComponentData";
    public static final String FETCH_POLICY = "fetchPolicy";
    public static final String SEC_EVENT = "sec_event";
    public static final String SEC_HEALTH_CHECK = "sec_health_check_lc";
    public static final String NR_ENTITY_GUID = "entityGuid";

    /**
     * Tool id for Language Agent.
     */
    @JsonInclude
    private static String collectorVersion;

    private String buildNumber;

    /**
     * The Json name.
     */
    private String jsonName;

    /**
     * Json version number.
     */
    private String jsonVersion;

    private final String collectorType = "JAVA";

    private final String language = "Java";

    private final String framework = StringUtils.EMPTY;

    private String groupName;

    private String nodeId;

    private String eventType;

    private Map<String, String> linkingMetadata;

    @JsonInclude
    private static String policyVersion;

    private boolean isPolicyOverridden = AgentUtils.getInstance().isPolicyOverridden();

    /**
     * Instantiates a new agent basic info according to the source class object.
     */
    public AgentBasicInfo() {
        setPolicyVersion(AgentUtils.getInstance().getAgentPolicy().getVersion());
        setJsonVersion(AgentInfo.getInstance().getBuildInfo().getJsonVersion());
        setCollectorVersion(AgentInfo.getInstance().getBuildInfo().getCollectorVersion());
        setBuildNumber(AgentInfo.getInstance().getBuildInfo().getBuildNumber());
        setGroupName(AgentConfig.getInstance().getGroupName());
        setNodeId(AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.NR_ENTITY_GUID, StringUtils.EMPTY));
        setLinkingMetadata(AgentInfo.getInstance().getLinkingMetadata());
        if (this instanceof ApplicationInfoBean) {
            setJsonName(JSON_NAME_APPLICATION_INFO_BEAN);
        } else if (this instanceof JavaAgentEventBean) {
            setJsonName(JSON_NAME_INTCODE_RESULT_BEAN);
            setEventType(SEC_EVENT);
        } else if (this instanceof JAHealthCheck) {
            setJsonName(JSON_NAME_HEALTHCHECK);
            setEventType(SEC_HEALTH_CHECK);
        } else if (this instanceof ShutDownEvent) {
            setJsonName(JSON_NAME_SHUTDOWN);
        } else if (this instanceof JavaAgentDynamicPathBean) {
            setJsonName(JSON_NAME_DYNAMICJARPATH_BEAN);
        } else if (this instanceof FuzzFailEvent) {
            setJsonName(JSON_NAME_FUZZ_FAIL);
        } else if (this instanceof HttpConnectionStat) {
            setJsonName(JSON_NAME_HTTP_CONNECTION_STAT);
        } else if (this instanceof PolicyFetch) {
            setJsonName(FETCH_POLICY);
        } else if (this instanceof ExitEventBean) {
            setJsonName(JSON_NAME_EXIT_EVENT);
        } else if (this instanceof ApplicationURLMappings) {
            setJsonName(JSON_SEC_APPLICATION_URL_MAPPING);
            setEventType(JSON_SEC_APPLICATION_URL_MAPPING);
        }
    }

    public String getPolicyVersion() {
        return AgentBasicInfo.policyVersion;
    }

    public void setPolicyVersion(String policyVersion) {
        AgentBasicInfo.policyVersion = policyVersion;
    }

    /**
     * Gets the Language Agent tool id.
     *
     * @return the Language Agent tool id.
     */
    public String getCollectorVersion() {
        return AgentBasicInfo.collectorVersion;
    }

    /**
     * Sets the Language Agent tool id.
     *
     * @param collectorVersion Language Agent tool id.
     */
    public void setCollectorVersion(String collectorVersion) {
        AgentBasicInfo.collectorVersion = collectorVersion;
    }

    /**
     * Gets the jsonName.
     *
     * @return the jsonName
     */
    public String getJsonName() {
        return jsonName;
    }

    /**
     * Sets the jsonName.
     *
     * @param jsonName the new jsonName
     */
    public void setJsonName(String jsonName) {
        this.jsonName = jsonName;
    }

    /**
     * Gets the version.
     *
     * @return the version
     */
    public String getJsonVersion() {
        return jsonVersion;
    }

    /**
     * Sets the version.
     *
     * @param jsonVersion the new version
     */
    public void setJsonVersion(String jsonVersion) {
        this.jsonVersion = jsonVersion;
    }

    public String getLanguage() {
        return language;
    }

    public String getFramework() {
        return framework;
    }

    /**
     * @return the collectorType
     */
    public String getCollectorType() {
        return collectorType;
    }

    public String getNodeId() {
        return nodeId;
    }

    public void setNodeId(String nodeId) {
        this.nodeId = nodeId;
    }
    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }

    public String getBuildNumber() {
        return buildNumber;
    }

    public void setBuildNumber(String buildNumber) {
        this.buildNumber = buildNumber;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public boolean isPolicyOverridden() {
        return isPolicyOverridden;
    }

    public void setPolicyOverridden(boolean policyOverridden) {
        isPolicyOverridden = policyOverridden;
    }


    public Map<String, String> getLinkingMetadata() {
        return linkingMetadata;
    }

    public void setLinkingMetadata(Map<String, String> linkingMetadata) {
        this.linkingMetadata = linkingMetadata;
    }
}
